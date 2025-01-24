DESTDIR ?= /usr/local
CFLAGS ?= -Wall
FPIC ?= -fpic

build: umap/core.so umap/crypto.so umap/socket/raw.so

umap/core.so: umap/core.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^

umap/crypto.so: umap/crypto.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^ -lcrypto

umap/socket/raw.so: umap/socket/raw.c
	$(CC) -shared -o $@ $(CFLAGS) $(FPIC) $^

install: build
	install -d \
		$(DESTDIR)/sbin \
		$(DESTDIR)/share/ucode/umap \
		$(DESTDIR)/lib/ucode/umap/socket
	install -m755 -T umap.uc $(DESTDIR)/sbin/umapd
	install -m644 -T umap/socket/raw.so $(DESTDIR)/lib/ucode/umap/socket/raw.so
	install -m644 umap/*.uc $(DESTDIR)/share/ucode/umap/



