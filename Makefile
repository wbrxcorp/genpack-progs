all: build-kernel.py

install: build-kernel.py
	mkdir -p /usr/local/sbin
	cp -a build-kernel.py /usr/local/sbin/build-kernel
	chmod +x /usr/local/sbin/build-kernel
