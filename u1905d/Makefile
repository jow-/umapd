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
endef

define Package/u1905d/description
  The u190d daemon is an implementation of the IEEE 1905.1 standard.
endef


define Package/u1905d/install
	$(INSTALL_DIR) $(1)/usr
        $(CP) $(PKG_INSTALL_DIR)/usr/* $(1)/usr/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/u1905d.init $(1)/etc/init.d/u1905d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/u1905d.config $(1)/etc/config/u1905d
endef

$(eval $(call BuildPackage,u1905d))
