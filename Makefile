all: build-kernel.py recursive-touch.py overlay-init.py with-mysql.py \
	download.py get-github-download-url.py init.bin genpack-install.bin

init.bin: init.cpp
	g++ -std=c++20 -static-libgcc -static-libstdc++ -o $@ $< -lblkid -lmount

genpack-install.bin: genpack-install.cpp
	g++ -std=c++23 -o  $@ $< -lmount -lblkid

install: build-kernel.py recursive-touch.py overlay-init.py with-mysql.py \
		download.py get-github-download-url.py init.bin genpack-install.bin
	mkdir -p /usr/local/sbin
	cp -a build-kernel.py /usr/local/sbin/build-kernel
	chmod +x /usr/local/sbin/build-kernel
	mkdir -p /usr/local/bin
	cp -a recursive-touch.py /usr/local/bin/recursive-touch
	chmod +x /usr/local/bin/recursive-touch
	cp -a overlay-init.py /usr/bin/overlay-init
	chmod +x /usr/bin/overlay-init
	cp -a check-outdated-packages.py /usr/bin/check-outdated-packages
	chmod +x /usr/bin/check-outdated-packages
	cp -a with-mysql.py /usr/local/sbin/with-mysql
	chmod +x /usr/local/sbin/with-mysql
	cp -a download.py /usr/local/bin/download
	chmod +x /usr/local/bin/download
	cp -a get-rpm-download-url.py /usr/local/bin/get-rpm-download-url
	chmod +x /usr/local/bin/get-rpm-download-url
	cp -a get-github-download-url.py /usr/local/bin/get-github-download-url
	chmod +x /usr/local/bin/get-github-download-url
	cp -a findelf.py /usr/local/bin/findelf
	chmod +x /usr/local/bin/findelf
	cp -a init.bin /init
	cp -a genpack-install.bin /usr/bin/genpack-install
	cp -a install-cloudflared.py /usr/bin/install-cloudflared
	chmod +x /usr/bin/install-cloudflared

clean:
	rm -f *.bin
