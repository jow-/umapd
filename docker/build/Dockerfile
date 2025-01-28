FROM scratch
#ADD --checksum=sha256:383311300e1fd796f5a39bf09ad87bcedec61a7f09263f79cd1352757a3573a9 https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-23.05.5-x86-64-rootfs.tar.gz /
ADD openwrt-23.05.5-x86-64-rootfs.tar.gz /
COPY libucode20230711_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode-mod-fs_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode-mod-nl80211_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode-mod-rtnl_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode-mod-socket_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode-mod-struct_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode-mod-ubus_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode-mod-uci_2025-01-25-5b747224_x86_64.ipk /root/
COPY ucode-mod-uloop_2025-01-25-5b747224_x86_64.ipk /root/
COPY umapd_1_x86_64.ipk /root/
COPY luci-app-umap_git-25.024.33302-be7e500_all.ipk /root/
RUN mkdir /var/lock && \
	opkg remove procd-ujail && \
	opkg update && \
	opkg install procd kmod-cfg80211 iw-full hostapd-openssl hostapd-utils wpa-supplicant-openssl && \
	rm -r /tmp/opkg-lists && \
	opkg install --force-reinstall --force-downgrade /root/*.ipk && \
	rm -r /var/lock && \
	rm /root/*.ipk
CMD ["/sbin/init"]
