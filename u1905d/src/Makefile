DESTDIR ?= /usr/local
CFLAGS ?= -Wall
FPIC ?= -fpic

TLV_SOURCES:=$(wildcard u1905/tlv/[0-9a-f][0-9a-f].uc)

build: u1905/core.so u1905/crypto.so u1905/socket/raw.so u1905/tlv/registry.uc

u1905/core.so: u1905/core.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^

u1905/crypto.so: u1905/crypto.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^ -lcrypto

u1905/socket/raw.so: u1905/socket/raw.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^

u1905/tlv/registry.uc: gen_tlv_registry.sh $(TLV_SOURCES)
	./gen_tlv_registry.sh > u1905/tlv/registry.uc

install: build
	install -d \
		$(DESTDIR)/sbin \
		$(DESTDIR)/share/ucode/u1905 \
		$(DESTDIR)/lib/ucode/u1905/socket
	install -m755 -T u1905.uc $(DESTDIR)/sbin/u1905d
	install -m644 -T u1905/socket/raw.so $(DESTDIR)/lib/ucode/u1905/socket/raw.so
	install -m644 u1905/*.uc $(DESTDIR)/share/ucode/u1905/



