#syntax=docker/dockerfile:1

ARG BUILD_CONTROLLER=0

FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y \
		build-essential \
		libncurses-dev \
		file \
		gawk \
		git \
		python3-setuptools \
		rsync \
		unzip \
		zstd \
		wget \
	&& rm -rf /var/lib/apt/lists/*

USER ubuntu
WORKDIR /build

ADD --chown=ubuntu --checksum=sha256:94f55f15599b57e3b341681d6deffa8e6ce38fc829e0ed14ad5c4f4a4d85a4dc https://downloads.openwrt.org/releases/24.10.0/targets/x86/64/openwrt-sdk-24.10.0-x86-64_gcc-13.3.0_musl.Linux-x86_64.tar.zst /tmp/sdk.archive
ADD --chown=ubuntu --checksum=sha256:25c1e8682bd3c4950be6480d859257bb5c86d5be36589824d43141986fe64d93 https://downloads.openwrt.org/releases/24.10.0/targets/x86/64/openwrt-24.10.0-x86-64-rootfs.tar.gz /tmp/rootfs.archive

RUN tar -C /build/ --strip-components=1 -xf /tmp/sdk.archive \
	&& { \
		echo "src-link local /src/"; \
		echo "src-git base https://github.com/openwrt/openwrt.git;openwrt-24.10"; \
		echo "src-git packages https://github.com/openwrt/packages.git;openwrt-24.10"; \
		echo "src-git luci https://github.com/openwrt/luci.git;openwrt-24.10"; \
	} > feeds.conf \
	&& ./scripts/feeds update base luci packages

COPY --chown=ubuntu ./ucode/ /src/ucode/
COPY --chown=ubuntu ./umapd/ /src/umapd/
COPY --chown=ubuntu ./luci-app-umap/ /src/luci-app-umap/

RUN ./scripts/feeds update local \
	&& ./scripts/feeds install -d y -p local \
		ucode umapd umap-agent umap-controller luci-app-umap \
	&& make defconfig \
	&& make -j $(nproc) package/ucode/compile package/umapd/compile package/luci-app-umap/compile V=sc

WORKDIR /rootfs

RUN tar -C /rootfs/ -xf /tmp/rootfs.archive

FROM scratch

COPY --from=builder /rootfs/ /
COPY --from=builder /build/bin/packages/x86_64/local/libucode*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode-mod-fs_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode-mod-nl80211_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode-mod-rtnl_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode-mod-socket_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode-mod-struct_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode-mod-ubus_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode-mod-uci_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/ucode-mod-uloop_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/umapd_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/umap-agent_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/umap-controller_*.ipk /root/
COPY --from=builder /build/bin/packages/x86_64/local/luci-app-umap_*.ipk /root/

RUN mkdir /var/lock && \
	opkg remove procd-ujail && \
	opkg update && \
	opkg install procd kmod-cfg80211 iw-full hostapd-openssl hostapd-utils wpa-supplicant-openssl tc-tiny && \
	rm -r /tmp/opkg-lists && \
	{ [ ${BUILD_CONTROLLER} = 1 ] || rm /root/umap-controller_*.ipk; } && \
	opkg install --force-reinstall --force-downgrade /root/*.ipk && \
	rm -r /var/lock && \
	rm /root/*.ipk

CMD ["/sbin/init"]
