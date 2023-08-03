#!/usr/bin/env sh

#
# Helper script to build all our example dissectors, and copies them to where Wireshark will search
#
cargo build --examples
epan_dir=~/.local/lib/wireshark/plugins/4.0/epan/
for file in wsdf/examples/*
do
	filename=$(basename -- "$file")
	example="${filename%.*}"
	shared_obj="target/debug/examples/lib${example}.so"
	cp "$shared_obj" "$epan_dir"
done
