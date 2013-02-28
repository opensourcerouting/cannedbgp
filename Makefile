love: cannedbgp
.PHONY: love

PKGS="libevent" # libpcre"

cannedbgp: main.o
	gcc -g -o $@ `pkg-config --libs $(PKGS)` -L../bgpdump -Wl,-rpath,../bgpdump -lbgpdump -lrt $^

clean:
	rm -f *.o cannedbgp

%.o: %.c
	gcc -c -g -O0 -Wall -Wextra -Wshadow -pedantic -Wno-unused-parameter -Wno-format -std=gnu99 `pkg-config --cflags $(PKGS)` -I../bgpdump -o $@ $<

