all: build-kernel.bin

build-kernel.zip: build-kernel.py
	zip build-kernel.zip build-kernel.py

build-kernel.bin: build-kernel.zip
	echo '#!/usr/bin/env python' | cat - $^ > $@
	chmod +x $@

install: build-kernel.bin
	mkdir -p /usr/local/sbin
	cp -a build-kernel.bin /usr/local/sbin/build-kernel
