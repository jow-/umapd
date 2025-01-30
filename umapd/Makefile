#
# Copyright (C) 2023-2025 Jo-Philipp Wich <jo@mein.io>
#
# This is free software, licensed under the Apache 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=umapd
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0

PKG_BUILD_DEPENDS:=ucode

include $(INCLUDE_DIR)/package.mk


define Package/umapd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Wireless EasyMesh daemon
  MAINTAINER:=Jo-Philipp Wich <jo@mein.io>
  DEPENDS:=+libopenssl
endef

define Package/umapd/description
  The umapd daemon is an implementation of the Wi-Fi EasyMesh standard.
endef

LIBS:=umap/*.so umap/socket/raw.so
MODS:=umap/*.uc umap/tlv/*.uc umap/*.uc

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

	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config $(1)/usr/libexec/umap
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/umap.uc $(1)/usr/sbin/umapd
	$(INSTALL_BIN) ./files/umapd.init $(1)/etc/init.d/umapd
	$(INSTALL_CONF) ./files/umapd.config $(1)/etc/config/umapd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wifi-apply.uc $(1)/usr/libexec/umap/wifi-apply
endef

$(eval $(call BuildPackage,umapd))
