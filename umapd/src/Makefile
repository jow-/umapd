DESTDIR ?= /usr/local
CFLAGS ?= -Wall
FPIC ?= -fpic

build: umap/core.so umap/crypto.so

umap/core.so: umap/core.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^

umap/crypto.so: umap/crypto.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^ -lcrypto

install: build
	install -d \
		$(DESTDIR)/sbin \
		$(DESTDIR)/share/ucode/umap \
		$(DESTDIR)/lib/ucode/umap
	install -m755 -T umap.uc $(DESTDIR)/sbin/umapd
	install -m644 -T umap/core.so $(DESTDIR)/lib/ucode/umap/core.so
	install -m644 -T umap/crypto.so $(DESTDIR)/lib/ucode/umap/crypto.so
	install -m644 umap/*.uc $(DESTDIR)/share/ucode/umap/
