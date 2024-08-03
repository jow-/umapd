#
# Copyright (C) 2023 Jo-Philipp Wich <jo@mein.io>
#
# This is free software, licensed under the Apache 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=u1905d
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0

include $(INCLUDE_DIR)/package.mk


define Package/u1905d
  SECTION:=net
  CATEGORY:=Network
  TITLE:=IEEE 1905.1 daemon
  MAINTAINER:=Jo-Philipp Wich <jo@mein.io>
  DEPENDS:=libopenssl
endef

define Package/u1905d/description
  The u190d daemon is an implementation of the IEEE 1905.1 standard.
endef

LIBS:=u1905/*.so u1905/socket/raw.so
MODS:=u1905/*.uc u1905/tlv/*.uc umap/*.uc

define Package/u1905d/install
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

	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/u1905.uc $(1)/usr/sbin/u1905d
	$(INSTALL_BIN) ./files/u1905d.init $(1)/etc/init.d/u1905d
	$(INSTALL_CONF) ./files/u1905d.config $(1)/etc/config/u1905d
endef

$(eval $(call BuildPackage,u1905d))
