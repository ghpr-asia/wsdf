#!/usr/bin/env sh

#
# Helper script to build all our example dissectors, and copies them to where Wireshark will search
#
cargo build --examples
epan_dir=
os_type="${OSTYPE%%[0-9]*}"

# Assuming users have Wireshark application installed under /Applications/Wireshark.app
# Reference: https://github.com/YuanYuYuan/zenoh-dissector-rs

case "$OSTYPE" in
  darwin*)  epan_dir=/Applications/Wireshark.app/Contents/PlugIns/wireshark/4-0/epan;; #macos
  linux*)   epan_dir=~/.local/lib/wireshark/plugins/4.0/epan/;;
  *)        echo "unknown: $OSTYPE" ;;
esac
shared_obj=



for file in wsdf/examples/*
do
	filename=$(basename -- "$file")
	example="${filename%.*}"
	if [ $os_type != "linux-gnu" ]; then
		shared_obj="target/debug/examples/lib${example}.dylib"
		cp "$shared_obj" "${epan_dir}/lib${example}.so"
	else
	   shared_obj="target/debug/examples/lib${example}.so"
		cp "$shared_obj" "$epan_dir"
	fi
	echo Copied $shared_obj
done
