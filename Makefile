DESTDIR ?= /usr/local
CFLAGS ?= -Wall
FPIC ?= -fpic

u1905/socket/raw.so: u1905/socket/raw.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^

install: u1905/socket/raw.so
	install -d \
		$(DESTDIR)/sbin \
		$(DESTDIR)/share/ucode/u1905 \
		$(DESTDIR)/lib/ucode/u1905/socket
	install -m755 -T u1905.uc $(DESTDIR)/sbin/u1905d
	install -m644 -T u1905/socket/raw.so $(DESTDIR)/lib/ucode/u1905/socket/raw.so
	install -m644 u1905/*.uc $(DESTDIR)/share/ucode/u1905/

