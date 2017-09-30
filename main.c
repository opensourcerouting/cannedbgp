/*
 Copyright (c) 2013  David Lamparter / Internet Systems Consortium, Inc.
 Copyright (c) 2013  Christian Franke / Internet Systems Consortium, Inc.

 Permission to use, copy, modify, and distribute this software and its
 documentation for any purpose and without fee is hereby granted, provided
 that the above copyright notice appear in all copies and that both that
 copyright notice and this permission notice appear in supporting
 documentation, and that the name of the author not be used in advertising or
 publicity pertaining to distribution of the software without specific,
 written prior permission.

 THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO EVENT SHALL
 AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
 DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


 This program links against libbgpdump, which contains code derived from GNU
 Zebra, used under the GNU General Public License.  Linked binaries therefore
 fall under the GNU GPL.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <bgpdump_lib.h>

struct event_base *ev_base;
static struct timespec start_ts;

FILE *plotfile = NULL;

union sockaddr_container {
		struct sockaddr_storage stor;
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
};

struct update {
	struct update *next;

	uint16_t afi;
	uint8_t prefixlen;

	union {
		struct in_addr in;
		struct in6_addr in6;
	} prefix;

	size_t attrlen;
	uint8_t *attr;
};

size_t peer_index;

struct peer {
	struct peer *next;

	union sockaddr_container bind;
	struct in_addr dump_router_id;
	size_t dump_index;
	uint32_t asn;

	struct update *updates, **pupdates;
	uint64_t updates_total, updates_failed, mem;

	struct update *sendpos;
	uint64_t sent_total, sent_aggr;

	uint64_t read_bytes;

	int fd;
	struct bufferevent *bev;

	union sockaddr_container adv_base;
	unsigned int adv_plen;
	union sockaddr_container adv_step;
	size_t adv_count;
	size_t adv_iter;
};

static struct peer *peers = NULL, **ppeers = &peers;
static struct peer **peersbyidx = NULL;
static volatile uint64_t routes_loaded = 0, routes_ignored = 0;

static void print_ts(FILE *f, struct timespec *ts)
{
	long srel, nsrel;

	srel = ts->tv_sec - start_ts.tv_sec;
	nsrel = ts->tv_nsec - start_ts.tv_nsec;
	if (nsrel < 0) {
		nsrel += 1000000000;
		srel -= 1;
	}

	fprintf(f, "%02d:%02d.%03lu ", srel / 60, srel % 60, nsrel / 1000000);
}

static void peer_prefix(FILE *f, struct peer *p)
{
	char rid[50], addr[50] = "[";
	inet_ntop(AF_INET, &p->dump_router_id, rid, sizeof(rid));
	inet_ntop(p->bind.sa.sa_family,
		p->bind.sa.sa_family == AF_INET ? (void *)&p->bind.in.sin_addr : (void *)&p->bind.in6.sin6_addr,
		addr + 1, sizeof(addr) - 2);
	addr[strlen(addr)] = ']';

	fprintf(f, "[%3d] AS%-7d %-15s %17s:%d ",
		p->dump_index, p->asn, rid, addr, ntohs(
			p->bind.sa.sa_family == AF_INET ? p->bind.in.sin_port : p->bind.in6.sin6_port));
}

static void peer_ev_read(struct bufferevent *bev, void *ctx)
{
	struct peer *p = ctx;
	struct evbuffer *in = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(in);

	p->read_bytes += len;
	evbuffer_drain(in, len);
}

static void peer_put_message(struct bufferevent *bev, struct evbuffer *buf)
{
	uint8_t marker[16];
	uint16_t msgsize;

	memset(marker, 0xff, sizeof(marker));
	bufferevent_write(bev, &marker, sizeof(marker));

	msgsize = htons(sizeof(marker) + sizeof(msgsize) + evbuffer_get_length(buf));
	bufferevent_write(bev, &msgsize, sizeof(msgsize));

	bufferevent_write_buffer(bev, buf);
}

#define AFI_IP 1
#define AFI_IP6 2

static struct update *peer_synth_update(struct peer *p)
{
	struct update *u = calloc(sizeof(*u),1);

	u->afi = (p->adv_base.in.sin_family == AF_INET) ? AFI_IP : AFI_IP6;
	u->prefixlen = p->adv_plen;

	if (u->afi == AFI_IP) {
		memcpy(&u->prefix.in, &p->adv_base.in.sin_addr, sizeof(u->prefix.in));
	} else {
		memcpy(&u->prefix.in6, &p->adv_base.in6.sin6_addr, sizeof(u->prefix.in6));
	}

	if (u->afi == AFI_IP6) {
		/* TODO: MP-BGP synth not implemented yet */
		return NULL;
	}

	/* Attributes:
	 * 8bit  attr. flags, 0x40 (transitive, well known)
	 * 8bit  attr. type,  0x01 (ORIGIN)
	 * 8bit  attr. len,      1 (len of attr)
	 * 8bit  attr. value,    0 (ORIGIN IGP)
	 * 8bit  attr. flags, 0x40 (transitive, well known)
	 * 8bit  attr. type,  0x02 (AS_PATH)
	 * 8bit  attr. len,      6 (len of attr)
	 *       attr. value:
	 *       8bit  type:     2 (AS_SEQUENCE)
	 *       8bit  len :     1 (1 AS)
	 *      32bit  val :   xxx (AS)
	 * 8bit  attr. flags, 0x40 (transitive, well known)
	 * 8bit  attr. type,  0x03 (NEXT_HOP)
	 * 8bit  attr. len,      4 (len of attr)
	 *       attr. value:  xxx (IP)
	 */


	uint8_t attributes[] = { 0x40, 0x01, 1, 0,
	                         0x40, 0x02, 6, 2, 1, 0xff, 0xff, 0xff, 0xff,
	                         0x40, 0x03, 4, 0xff, 0xff, 0xff, 0xff };

	uint32_t attr_as = htonl(p->asn);
	memcpy(&attributes[9], &attr_as, sizeof(attr_as));
	memcpy(&attributes[16], &p->bind.in.sin_addr, sizeof(p->bind.in.sin_addr));

	u->attr = malloc(sizeof(attributes));
	memcpy(u->attr, attributes, sizeof(attributes));
	u->attrlen = sizeof(attributes);

	return u;
}

static struct update *peer_first_sendpos(struct peer *p)
{
	if (!p->adv_count)
		return p->updates; /* MRT peer */

	return peer_synth_update(p);
}

static struct update *peer_synth_update_iter(struct peer *p)
{
	p->adv_iter++;

	if (p->adv_iter == p->adv_count) {
		free(p->sendpos->attr);
		free(p->sendpos);
		return NULL;
	}

	p->sendpos->prefix.in.s_addr = htonl(ntohl(p->sendpos->prefix.in.s_addr)
	                                   + ntohl(p->adv_step.in.sin_addr.s_addr));
	return p->sendpos;
}

static struct update *peer_next_sendpos(struct peer *p)
{
	if (!p->adv_count)
		return p->sendpos->next; /* MRT peer */

	return peer_synth_update_iter(p);
}

static void peer_ev_write(struct bufferevent *bev, void *ctx)
{
	struct peer *p = ctx;
	struct evbuffer *out = evbuffer_new();

	uint8_t prefixbytes;
	uint8_t type = 2;
	uint16_t withdrawsize = 0;
	uint16_t attrsize;

	if (!p->sendpos) {
		bufferevent_disable(p->bev, EV_WRITE);
		return;
	}

	evbuffer_add(out, &type, sizeof(type));
	evbuffer_add(out, &withdrawsize, sizeof(withdrawsize));
	attrsize = htons(p->sendpos->attrlen);
	evbuffer_add(out, &attrsize, sizeof(attrsize));
	evbuffer_add(out, p->sendpos->attr, p->sendpos->attrlen);

	attrsize = p->sendpos->attrlen;
	uint8_t *attrbuf = malloc(attrsize);
	memcpy(attrbuf, p->sendpos->attr, attrsize);

	/* XXX: This could probably be optimized, the current implementation
	 * doesn't aggreagate IPv6 at all. However this is a bit more tricky
	 * than IPv4 as we have to do the aggreation in the MP-BGP attribute.
	 */
	if (p->sendpos->afi == AFI_IP) {
		while (p->sendpos && p->sendpos->attrlen == attrsize
		       && !memcmp(p->sendpos->attr, attrbuf, attrsize)
		       && evbuffer_get_length(out) < 4096 - 19 - (p->sendpos->prefixlen + 7) / 8) {
			if (p->sendpos->afi != AFI_IP)
			  break;
			prefixbytes = (p->sendpos->prefixlen + 7) / 8;
			evbuffer_add(out, &p->sendpos->prefixlen, sizeof(p->sendpos->prefixlen));
			evbuffer_add(out, &p->sendpos->prefix, prefixbytes);

			p->sent_total++;
			p->sent_aggr++;
			p->sendpos = peer_next_sendpos(p);
		}
		p->sent_aggr--;
	} else {
		p->sent_total++;
		p->sendpos = p->sendpos->next;
	}

	free(attrbuf);
	peer_put_message(bev, out);
	evbuffer_free(out);

	if (!p->sendpos) {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);

		print_ts(stdout, &ts);
		peer_prefix(stdout, p);
		printf("done sending %lu updates!\033[K\n", p->sent_total);

		uint64_t sent = 0;
		for (p = peers; p; p = p->next) {
			sent += p->sent_total;
			if (p->sendpos)
				break;
		}
		if (!p) {
			print_ts(stdout, &ts);
			printf("- loading completed, %llu updates at %9.1lf upd/sec\033[K\n",
				sent, sent / ((ts.tv_sec - start_ts.tv_sec) + (ts.tv_nsec - start_ts.tv_nsec) * 0.000000001)
			);
			fflush(stdout);
		}
	}
}

static void peer_send_open(struct peer *p)
{
	struct evbuffer *out = evbuffer_new();
	uint8_t blk1[] = { 1, 4 };
	uint8_t optional[] = {
		/* MP-BGP IPv4 */
		2, 6, 1, 4, 0, 1, 0, 1,
		/* MP-BGP IPv6 Unicast */
		2, 6, 1, 4, 0, 2, 0, 1,
		/* AS4 */
		2, 6, 0x41, 4, p->asn >> 24, p->asn >> 16, p->asn >> 8, p->asn
	};
	uint8_t blk2[] = { 0, 180 };
	uint8_t blk3[] = { sizeof(optional) };
	uint16_t tmp;

	evbuffer_add(out, blk1, sizeof(blk1));
	if (p->asn > 65535)
		tmp = htons(23456);
	else
		tmp = htons(p->asn);
	evbuffer_add(out, &tmp, sizeof(tmp));
	evbuffer_add(out, blk2, sizeof(blk2));
	evbuffer_add(out, &p->dump_router_id, sizeof(p->dump_router_id));
	evbuffer_add(out, blk3, sizeof(blk3));
	evbuffer_add(out, optional, sizeof(optional));

	peer_put_message(p->bev, out);
	evbuffer_free(out);
}

static void peer_send_keepalive(struct peer *p)
{
	struct evbuffer *out = evbuffer_new();
	uint8_t blk1[] = { 4 };

	evbuffer_add(out, blk1, sizeof(blk1));
	peer_put_message(p->bev, out);
	bufferevent_enable(p->bev, EV_WRITE);
	evbuffer_free(out);
}

static void peer_ev_other(struct bufferevent *bev, short what, void *ctx)
{
	struct peer *p = ctx;
	const char *action =
		(what & 0x0f) == BEV_EVENT_READING ? "reading" :
		(what & 0x0f) == BEV_EVENT_WRITING ? "writing" :
		"?";

	if (what & BEV_EVENT_EOF) {
		printf("\n");
		peer_prefix(stderr, p);
		fprintf(stderr, "EOF %s at %lu of %lu sent\n", action,
			p->sent_total, p->updates_total);
		what &= ~BEV_EVENT_EOF;
		exit(0);
	}
	if (what & BEV_EVENT_ERROR) {
		peer_prefix(stderr, p);
		fprintf(stderr, "error %s, last errno %s\n", action, strerror(errno));
		what &= ~BEV_EVENT_ERROR;
	}
	if (what & ~0xfU) {
		peer_prefix(stderr, p);
		fprintf(stderr, "unknown event 0x%02x while %s\n", what, action);
	}
	bufferevent_free(bev);
	p->bev = NULL;
	p->fd = -1;
}

static void evt_keepalive_tick(int fd, short what, void *ctx)
{
	struct peer *p;
	size_t n = 0;
	for (p = peers; p; p = p->next)
		if (p->fd != -1 && p->bev) {
			peer_send_keepalive(p);
			n++;
		}
	printf("%zu keepalives sent\033[K\n", n);
}

static void sigalrm(int sig)
{
	printf("loading: %7llu prepared, %7llu ignored\r", routes_loaded, routes_ignored);
	fflush(stdout);
}

static void evt_info_tick(int fd, short what, void *ctx)
{
	struct peer *p;
	static uint64_t last_sent = 0;
	uint64_t loading = 0, done = 0, disconn = 0, sent = 0, aggr = 0;
	static struct timespec last_ts;
	struct timespec ts;
	static double lazyrate = 0.0;
	double rate;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (plotfile)
		print_ts(plotfile, &ts);

	for (p = peers; p; p = p->next) {
		if (p->fd == -1 || !p->bev)
			disconn++;
		else if (!p->sendpos)
			done++;
		else
			loading++;
		sent += p->sent_total;
		aggr += p->sent_aggr;
		if (plotfile)
			fprintf(plotfile, ",%llu", p->sent_total);
	}

	rate = (sent - last_sent) / ((ts.tv_sec - last_ts.tv_sec) + (ts.tv_nsec - last_ts.tv_nsec) * 0.000000001);
	lazyrate = lazyrate * 0.9 + rate * 0.1;

	print_ts(stdout, &ts);
	printf("%3llu load, %3llu done, %3llu err.  %7llu / %7llu total (%7llu aggr). %9.1lf (%9.1lf) upd/sec\033[K\r",
		loading, done, disconn, sent, routes_loaded, aggr,
		lazyrate, rate);
	fflush(stdout);

	if (plotfile)
		fprintf(plotfile, "\n");

	last_sent = sent;
	last_ts = ts;
}

static void load_entry(BGPDUMP_ENTRY *e)
{
	struct peer *p;
	struct update *u;
	size_t i;
	BGPDUMP_TABLE_DUMP_V2_PREFIX *ee = &e->body.mrtd_table_dump_v2_prefix;

	if (e->type != BGPDUMP_TYPE_TABLE_DUMP_V2) {
		fprintf(stderr, "unknown entry type %d\n", e->type);
		return;
	}
	if (ee->afi != AFI_IP && ee->afi != AFI_IP6)
		return;

	for (i = 0; i < ee->entry_count; i++) {
		BGPDUMP_TABLE_DUMP_V2_ROUTE_ENTRY *re = &ee->entries[i];
		p = peersbyidx[re->peer_index];
		if (!p) {
			routes_ignored++;
			continue;
		}
		if (re->attr->aspath && re->attr->aspath->asn_len != 4) {
			fprintf(stderr, "cannot process AS2!\n");
			p->updates_failed++;
			continue;
		}

		/* XXX: Mandatory attribute, but what's the actual
		 * content on MP-BGP with only IPv6 ? */
		if (!re->attr->nexthop.s_addr) {
			fprintf(stderr, "empty nexthop\n");
			p->updates_failed++;
			continue;
		}

		u = calloc(sizeof(struct update), 1);
		p->mem += sizeof(struct update);

		u->afi = ee->afi;
		u->prefixlen = ee->prefix_length;
		memcpy(&u->prefix, &ee->prefix, sizeof(u->prefix));

		u->attrlen = re->attr->len;
		u->attr = malloc(re->attr->len);
		p->mem += re->attr->len;

		memcpy(u->attr, re->attr->data, re->attr->len);

		p->pupdates = &(*(p->pupdates) = u)->next;
		p->updates_total++;
		routes_loaded++;
	}
}

static int peer_connect(struct peer *p)
{
	socklen_t socklen = (p->bind.in.sin_family == AF_INET) ? sizeof(struct sockaddr_in)
							       : sizeof(struct sockaddr_in6);
	p->fd = socket(p->bind.sa.sa_family, SOCK_STREAM, 0);
	if (p->fd == -1) {
		fprintf(stderr, "failed to open socket for peer\n");
		return 1;
	}
	if (bind(p->fd, &p->bind.sa, socklen)) {
		fprintf(stderr, "failed to bind socket for peer: %s\n", strerror(errno));
		return 1;
	}
	getsockname(p->fd, &p->bind.sa, &socklen);
	return 0;
}

static int cannedbgp_load_dump(const char *inpfile, int optind, int argc, char *argv[])
{
	BGPDUMP *my_dump = bgpdump_open_dump(inpfile);
	struct itimerval itv;
	size_t i;
	struct peer *p;

	if (!my_dump) {
		fprintf(stderr, "failed to open %s\n", inpfile);
		return 1;
	}
	do {
		bgpdump_read_next(my_dump);
	} while (!my_dump->table_dump_v2_peer_index_table);
	if (!my_dump->table_dump_v2_peer_index_table) {
		fprintf(stderr, "failed to grab peer table from %s\n", inpfile);
		return 1;
	}
	peersbyidx = calloc(sizeof(struct peer *), my_dump->table_dump_v2_peer_index_table->peer_count);
	printf("dump %s contains %d peers\n", inpfile, my_dump->table_dump_v2_peer_index_table->peer_count);

	for (; optind < argc; optind++) {
		p = calloc(sizeof(struct peer), 1);
		i = atoi(argv[optind]);

		if (i >= my_dump->table_dump_v2_peer_index_table->peer_count) {
			fprintf(stderr, "cannot find peer %s in dump\n", argv[optind]);
		} else {
			if (my_dump->table_dump_v2_peer_index_table->entries[i].afi == AFI_IP) {
				p->bind.in.sin_family = AF_INET;
				p->bind.in.sin_addr = my_dump->table_dump_v2_peer_index_table->entries[i].peer_ip.v4_addr;
			} else if (my_dump->table_dump_v2_peer_index_table->entries[i].afi == AFI_IP6) {
				p->bind.in6.sin6_family = AF_INET6;
				p->bind.in6.sin6_addr = my_dump->table_dump_v2_peer_index_table->entries[i].peer_ip.v6_addr;
			} else {
				fprintf(stderr, "Peer %d has unsupported afi 0x%x\n", i,
					my_dump->table_dump_v2_peer_index_table->entries[i].afi);
				free(p);
				continue;
			}

			p->dump_router_id = my_dump->table_dump_v2_peer_index_table->entries[i].peer_bgp_id;
			if (!p->dump_router_id.s_addr) {
				fprintf(stderr, "skipping peer %d due to zero router-id\n", i);
				free(p);
				continue;
			}

			p->dump_index = i;
			p->asn = my_dump->table_dump_v2_peer_index_table->entries[i].peer_as;
			peersbyidx[p->dump_index] = p;

			int rv = peer_connect(p);
			if (rv)
				return rv;
		}
		p->pupdates = &p->updates;
		ppeers = &((*ppeers = p)->next);
	}

	for (i = 0; i < my_dump->table_dump_v2_peer_index_table->peer_count; i++) {
		BGPDUMP_TABLE_DUMP_V2_PEER_INDEX_TABLE_ENTRY *pe = &my_dump->table_dump_v2_peer_index_table->entries[i];
		char rid[50], addr[50];
		inet_ntop(AF_INET, &pe->peer_bgp_id, rid, sizeof(rid));
		inet_ntop(pe->afi == AFI_IP ? AF_INET : AF_INET6, &pe->peer_ip, addr, sizeof(addr));

		printf("[%3d] AS%-7d %-15s %s => ", i, pe->peer_as, rid, addr);
		if (peersbyidx[i]) {
			printf("loaded.\n");
		} else {
			printf("ignored.\n");
		}
	}

	signal(SIGALRM, &sigalrm);
	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 100000;
	itv.it_value.tv_sec = 0;
	itv.it_value.tv_usec = 100000;
	setitimer(ITIMER_REAL, &itv, NULL);

	do {
		BGPDUMP_ENTRY *my_entry = bgpdump_read_next(my_dump);
		if (my_entry) {
			load_entry(my_entry);
			bgpdump_free_mem(my_entry);
		}
	} while (!my_dump->eof);

	itv.it_interval.tv_sec = 0;
	itv.it_interval.tv_usec = 0;
	itv.it_value.tv_sec = 0;
	itv.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &itv, NULL);
	signal(SIGALRM, SIG_IGN);
	printf("\n");

	bgpdump_close_dump(my_dump);
	return 0;
}

static int cannedbgp_add_synth_peer(const char *peerspec)
{
	char *ps = strdup(peerspec);
	struct peer *p = calloc(sizeof(struct peer), 1);
	
	char *addr = strtok(ps, ",");
	char *as = strtok(NULL, ",");
	char *adv_base = strtok(NULL, ",");
	char *adv_plen = strtok(NULL, ",");
	char *adv_step = strtok(NULL, ",");
	char *adv_count = strtok(NULL, ",");

	if (!addr) {
		fprintf(stderr, "addr missing in peerspec\n");
		return 1;
	}

	if (inet_pton(AF_INET, addr, &p->bind.in.sin_addr) == 1) {
		p->bind.in.sin_family = AF_INET;
	} else if (inet_pton(AF_INET6, addr, &p->bind.in6.sin6_addr) == 1) {
		p->bind.in6.sin6_family = AF_INET6;
	} else {
		fprintf(stderr, "Could not parse peerspec addr\n");
		return 1;
	}

	peer_index++;

	p->dump_index = peer_index;
	p->dump_router_id = p->bind.in.sin_addr; /* FIXME: Quirky for v6 */
	if (!p->dump_router_id.s_addr)
		p->dump_router_id.s_addr = htonl(peer_index);

	if (!as) {
		fprintf(stderr, "as missing in peerspec\n");
		return 1;
	}
	p->asn = strtoul(as, NULL, 10);

	if (!adv_base) {
		fprintf(stderr, "adv_base missing in peerspec\n");
		return 1;
	}
	if (inet_pton(AF_INET, adv_base, &p->adv_base.in.sin_addr) == 1) {
		p->adv_base.in.sin_family = AF_INET;
	} else if (inet_pton(AF_INET, adv_base, &p->adv_base.in6.sin6_addr) == 1) {
		p->adv_base.in6.sin6_family = AF_INET6;
	} else {
		fprintf(stderr, "Could not parse peerspec adv_base\n");
		return 1;
	}

	if (!adv_plen) {
		fprintf(stderr, "adv_plen missing in peerspec\n");
		return 1;
	}
	p->adv_plen = strtoul(adv_plen, NULL, 10);
	if ((p->adv_base.in.sin_family == AF_INET && p->adv_plen > 32)
	    || (p->adv_base.in6.sin6_family == AF_INET6 && p->adv_plen > 128)) {
		fprintf(stderr, "Peerspec prefixlen is invalid.\n");
		return 1;
	}

	if (!adv_step) {
		fprintf(stderr, "adv_step missing in peerspec\n");
		return 1;
	}
	if ((p->adv_base.in.sin_family == AF_INET
	     && inet_pton(AF_INET, adv_step, &p->adv_step.in.sin_addr) != 1)
	    || (p->adv_base.in6.sin6_family == AF_INET6
	        && inet_pton(AF_INET6, adv_step, &p->adv_step.in6.sin6_addr) != 1)) {
		fprintf(stderr, "Peerspec adv_step is invalid.\n");
		return 1;
	}

	if (!adv_count) {
		fprintf(stderr, "adv_count missing in peerspec\n");
		return 1;
	}
	p->adv_count = strtoul(adv_count, NULL, 10);
	p->updates_total = p->adv_count;

	int rv = peer_connect(p);
	if (rv)
		return rv;

	ppeers = &((*ppeers = p)->next);
	return 0;
}

int main(int argc, char **argv)
{
	int optch = 0;
	const char *inpfile = NULL, *dhost = NULL;
	struct event *evt_info, *evt_keepalive;
	struct timeval tv;
	int rv;

	union sockaddr_container dst;

	do {
		optch = getopt(argc, argv, "i:d:G:s:");
		switch (optch) {
		case 'i':
			inpfile = optarg;
			break;
		case 'd':
			dhost = optarg;
			break;
		case 'G':
			plotfile = fopen(optarg, "w");
			if (!plotfile) {
				fprintf(stderr, "failed to open plot file %s: %s\n", optarg, strerror(errno));
				return 1;
			}
			break;
		case 's':
			rv = cannedbgp_add_synth_peer(optarg);
			if (rv)
				return rv;
			break;
		case -1:
			break;
		}
	} while (optch != -1);

	if (!inpfile && !peers) {
		fprintf(stderr, "specify input file with -i or synth peer with -s\n");
		return 1;
	}
	if (!dhost) {
		fprintf(stderr, "specify destination host with -d\n");
		return 1;
	}
	if (inet_pton(AF_INET, dhost, &dst.in.sin_addr) == 1) {
		dst.in.sin_family = AF_INET;
		dst.in.sin_port = htons(179);
	} else if (inet_pton(AF_INET6, dhost, &dst.in6.sin6_addr) == 1) {
		dst.in6.sin6_family = AF_INET6;
		dst.in6.sin6_port = htons(179);
	} else {
		fprintf(stderr, "invalid destination host %s\n", dhost);
		return 1;
	}

	if (inpfile) {
		rv = cannedbgp_load_dump(inpfile, optind, argc, argv);
		if (rv)
			return rv;
	}

	ev_base = event_base_new();

	for (struct peer *p = peers; p; p = p->next) {
		peer_prefix(stdout, p);
		printf("- %lu loaded (%lu kB), %lu errors\n",
			p->updates_total, (p->mem + 1023) / 1024, p->updates_failed);

		if (connect(p->fd, (struct sockaddr *)&dst,
				(dst.sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
			fprintf(stderr, "failed to connect: %s\n", strerror(errno));
			return 1;
		}
		p->sendpos = peer_first_sendpos(p);
		p->bev = bufferevent_socket_new(ev_base, p->fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		bufferevent_setcb(p->bev, peer_ev_read, peer_ev_write, peer_ev_other, p);
		bufferevent_setwatermark(p->bev, EV_READ, 1, 8192);
		bufferevent_setwatermark(p->bev, EV_WRITE, 1, 8192);
		bufferevent_enable(p->bev, EV_READ | EV_WRITE);
		peer_send_open(p);
		peer_send_keepalive(p);
	}

	evt_info = event_new(ev_base, -1, EV_PERSIST, evt_info_tick, NULL);
	tv.tv_sec = 0;
	tv.tv_usec = 200000;
	event_add(evt_info, &tv);

	evt_keepalive = event_new(ev_base, -1, EV_PERSIST, evt_keepalive_tick, NULL);
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	event_add(evt_keepalive, &tv);

	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	while (1) {
		fprintf(stderr, "starting to push data.\n");
		event_base_loop(ev_base, 0);
	}
	return 0;
}
