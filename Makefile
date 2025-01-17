all: build-kernel.py recursive-touch.py overlay-init.py with-mysql.py \
	download.py get-github-download-url.py init.bin

init.bin: init.cpp
	g++ -std=c++20 -static-libgcc -static-libstdc++ -o $@ $< -lblkid -lmount

install: build-kernel.py recursive-touch.py overlay-init.py with-mysql.py \
		download.py get-github-download-url.py
	mkdir -p $(DESTDIR)/usr/local/sbin
	cp -a build-kernel.py $(DESTDIR)/usr/local/sbin/build-kernel
	chmod +x $(DESTDIR)/usr/local/sbin/build-kernel
	mkdir -p $(DESTDIR)/usr/local/bin
	cp -a recursive-touch.py $(DESTDIR)/usr/local/bin/recursive-touch
	chmod +x $(DESTDIR)/usr/local/bin/recursive-touch
	mkdir -p $(DESTDIR)/usr/bin
	cp -a overlay-init.py $(DESTDIR)/usr/bin/overlay-init
	chmod +x $(DESTDIR)/usr/bin/overlay-init
	cp -a check-outdated-packages.py $(DESTDIR)/usr/bin/check-outdated-packages
	chmod +x $(DESTDIR)/usr/bin/check-outdated-packages
	cp -a with-mysql.py $(DESTDIR)/usr/local/sbin/with-mysql
	chmod +x $(DESTDIR)/usr/local/sbin/with-mysql
	cp -a download.py $(DESTDIR)/usr/local/bin/download
	chmod +x $(DESTDIR)/usr/local/bin/download
	cp -a get-rpm-download-url.py $(DESTDIR)/usr/local/bin/get-rpm-download-url
	chmod +x $(DESTDIR)/usr/local/bin/get-rpm-download-url
	cp -a get-github-download-url.py $(DESTDIR)/usr/local/bin/get-github-download-url
	chmod +x $(DESTDIR)/usr/local/bin/get-github-download-url
	cp -a findelf.py $(DESTDIR)/usr/local/bin/findelf
	chmod +x $(DESTDIR)/usr/local/bin/findelf
	cp -a install-cloudflared.py $(DESTDIR)/usr/bin/install-cloudflared
	chmod +x $(DESTDIR)/usr/bin/install-cloudflared
	cp -a genpack-get-all-package-files.py $(DESTDIR)/usr/bin/genpack-get-all-package-files
	chmod +x $(DESTDIR)/usr/bin/genpack-get-all-package-files

clean:
	rm -f *.bin
