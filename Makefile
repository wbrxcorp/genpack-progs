all: build-kernel.py recursive-touch.py overlay-init.py with-mysql.py init.bin genpack-install.bin

init.bin: init.cpp
	g++ -std=c++20 -static-libgcc -static-libstdc++ -o $@ $< -lblkid -lmount

genpack-install.bin: genpack-install.cpp
	g++ -std=c++23 -o  $@ $< -lmount -lblkid

install: build-kernel.py recursive-touch.py init.bin
	mkdir -p /usr/local/sbin
	cp -a build-kernel.py /usr/local/sbin/build-kernel
	chmod +x /usr/local/sbin/build-kernel
	mkdir -p /usr/local/bin
	cp -a recursive-touch.py /usr/local/bin/recursive-touch
	chmod +x /usr/local/bin/recursive-touch
	cp -a overlay-init.py /usr/bin/overlay-init
	chmod +x /usr/bin/overlay-init
	cp -a with-mysql.py /usr/local/sbin/with-mysql
	chmod +x /usr/local/sbin/with-mysql
	cp -a init.bin /init
	cp -a genpack-install.bin /usr/bin/genpack-install

clean:
	rm -f *.bin
