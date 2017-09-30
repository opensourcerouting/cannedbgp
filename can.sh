#!/bin/sh

gen_synth_spec() {
	echo "100.100.0.$1,$1,$1.0.0.0,24,0.0.1.0,25000"
}

gen_synth_specs() {
	for i in $(seq 1 $1); do
		if [ $i -eq 100 ]; then
			continue;
		fi
		echo "-s $(gen_synth_spec $i)"
	done
}

./cannedbgp -d 100.100.0.254 $(gen_synth_specs $1)
