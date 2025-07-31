#
# Copyright (C) 2023-2025 Jo-Philipp Wich <jo@mein.io>
#
# This is free software, licensed under the Apache 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=umapd
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0

PKG_BUILD_DEPENDS:=ucode bpf-headers

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk


define Package/umapd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Wireless EasyMesh daemon
  MAINTAINER:=Jo-Philipp Wich <jo@mein.io>
  DEPENDS:=+libopenssl +ucode \
	+ucode-mod-fs +ucode-mod-nl80211 +ucode-mod-rtnl +ucode-mod-socket \
	+ucode-mod-struct +ucode-mod-ubus +ucode-mod-uci +ucode-mod-uloop \
	+ucode-mod-udebug +ucode-mod-bpf +kmod-veth $(BPF_DEPENDS)
endef

define Package/umapd/description
  The umapd daemon is an implementation of the Wi-Fi EasyMesh standard.
endef

define Build/Compile
	$(call Build/Compile/Default)
	$(call CompileBPF,$(PKG_BUILD_DIR)/umap-bpf.c)
endef

LIBS:=umap/*.so
MODS:=umap/*.uc umap/tlv/*.uc umap/proto/*.uc umap/*.uc

define Package/umapd/install
	$(foreach dir,$(dir $(LIBS)),$(INSTALL_DIR) $(1)/usr/lib/ucode/$(dir); )
	$(foreach file,$(LIBS), \
		$(INSTALL_BIN) \
			$(addprefix $(PKG_BUILD_DIR)/,$(file)) \
			$(1)/usr/lib/ucode/$(dir $(file)); )

	$(foreach dir,$(dir $(MODS)),$(INSTALL_DIR) $(1)/usr/share/ucode/$(dir); )
	$(foreach file,$(MODS), \
		$(INSTALL_DATA) \
			$(addprefix $(PKG_BUILD_DIR)/,$(file)) \
			$(1)/usr/share/ucode/$(dir $(file)); )

	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/config $(1)/usr/libexec/umap $(1)/lib/bpf
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/umap.uc $(1)/usr/sbin/umapd
	$(INSTALL_CONF) ./files/umapd.config $(1)/etc/config/umapd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wifi-apply.uc $(1)/usr/libexec/umap/wifi-apply
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/umap-bpf.o $(1)/lib/bpf/umap.o
endef

define Package/umap-agent
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Wireless EasyMesh agent
  MAINTAINER:=Jo-Philipp Wich <jo@mein.io>
  DEPENDS:=+umapd +tc-tiny
endef

define Package/umap-agent/description
  This package bundles support and integration files to run the EasyMesh
  daemon as agent instance.
endef

define Package/umap-agent/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/uci-defaults $(1)/usr/libexec/umap $(1)/etc/rc.button
	$(INSTALL_BIN) ./files/umapd.agent.init $(1)/etc/init.d/umap-agent
	$(INSTALL_DATA) ./files/umapd.agent.defaults $(1)/etc/uci-defaults/umap-agent
	$(INSTALL_BIN) ./src/wps-connect.uc $(1)/usr/libexec/umap/wps-connect
	$(INSTALL_BIN) ./files/umap-agent.button $(1)/etc/rc.button/umap-agent
endef

define Package/umap-controller
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Wireless EasyMesh controller
  MAINTAINER:=Jo-Philipp Wich <jo@mein.io>
  DEPENDS:=+umapd
endef

define Package/umap-controller/description
  This package bundles support and integration files to run the EasyMesh
  daemon as network controller.
endef

define Package/umap-controller/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/uci-defaults $(1)/etc/rc.button
	$(INSTALL_BIN) ./files/umapd.controller.init $(1)/etc/init.d/umap-controller
	$(INSTALL_DATA) ./files/umapd.controller.defaults $(1)/etc/uci-defaults/umap-controller
	$(INSTALL_BIN) ./files/umap-controller.button $(1)/etc/rc.button/umap-controller
endef

$(eval $(call BuildPackage,umapd))
$(eval $(call BuildPackage,umap-agent))
$(eval $(call BuildPackage,umap-controller))
