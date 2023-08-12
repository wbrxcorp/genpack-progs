all: build-kernel.py recursive-touch.py

install: build-kernel.py recursive-touch.py
	mkdir -p /usr/local/sbin
	cp -a build-kernel.py /usr/local/sbin/build-kernel
	chmod +x /usr/local/sbin/build-kernel
	mkdir -p /usr/local/bin
	cp -a recursive-touch.py /usr/local/bin/recursive-touch
	chmod +x /usr/local/bin/recursive-touch
