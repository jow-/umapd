/*
 * Copyright (c) 2022 Jo-Philipp Wich <jo@mein.io>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

const nl80211 = require('nl80211');
const struct = require('struct');
const rtnl = require('rtnl');
const fs = require('fs');

const socket = require('u1905.socket');
const utils = require('u1905.utils');
const cmdu = require('u1905.cmdu');
const tlv = require('u1905.tlv');
const log = require('u1905.log');
const ubus = require('u1905.ubus');
const defs = require('u1905.defs');

function timems() {
	let tv = clock(true) ?? clock(false);
	return tv[0] * 1000 + tv[1] / 1000000;
}

function resolve_bridge_ports(ifname) {
	let bridge, vlan, link;
	let upper = ifname;

	while (true) {
		link = rtnl.request(rtnl.const.RTM_GETLINK, 0, { dev: upper });

		if (!link)
			return null;

		switch (link.linkinfo?.type) {
		case 'vlan':
			upper = link.link;
			vlan = link.linkinfo.id;
			continue;

		case 'bridge':
			bridge = upper;
			break;
		}

		break;
	}

	let links = [];

	if (bridge) {
		let bridge_links = rtnl.request(
			rtnl.const.RTM_GETLINK,
			rtnl.const.NLM_F_DUMP|rtnl.const.NLM_F_STRICT_CHK,
			{ master: bridge }
		);

		if (vlan) {
			let bridge_vlans = rtnl.request(
				rtnl.const.RTM_GETLINK,
				rtnl.const.NLM_F_DUMP, {
				family: rtnl.const.AF_BRIDGE,
				ext_mask: 2
			});

			if (bridge_vlans) {
				for (let link in bridge_vlans) {
					if (link.master != bridge || link.dev == link.master)
						continue;

					for (let vi in link.af_spec?.bridge?.bridge_vlan_info) {
						if (vi.vid > vlan || (vi.vid_end ?? vi.vid) < vlan)
							continue;

						if (vi.flags & rtnl.const.BRIDGE_VLAN_INFO_UNTAGGED)
							push(links, { ifname: link.ifname, address: link.address });
						else
							push(links, { ifname: link.ifname, address: link.address, vlan });

						break;
					}
				}
			}
			else {
				for (let link in bridge_links)
					push(links, { ifname: link.ifname, address: link.address, vlan });
			}
		}
		else {
			for (let link in bridge_links)
				push(links, { ifname: link.ifname, address: link.address });
		}
	}
	else {
		push(links, { ifname: link.ifname, address: link.address });
	}

	return links;
}

const I1905Entity = {
	update: function() {
		this.seen = timems();
	}
};

const I1905RemoteInterface = proto({
	new: function(address, i1905dev) {
		return proto({
			dev: i1905dev,
			address,
			seen: timems(),
			seen_lldp: 0,
			seen_cmdu: 0
		}, this);
	},

	updateLLDPTimestamp: function() {
		this.seen_lldp = timems();
	},

	updateCMDUTimestamp: function() {
		this.seen_cmdu = timems();
	},

	isBridged: function() {
		let diff;

		if (this.seen_cmdu > this.seen_lldp)
			diff = this.seen_cmdu - this.seen_lldp;
		else
			diff = this.seen_lldp - this.seen_cmdu;

		return (diff >= 120000);
	},

	getDevice: function() {
		return this.dev;
	}
}, I1905Entity);

const I1905LocalInterface = proto({
	new: function(link, i1905rxsock, i1905txsock, lldprxsock, lldptxsock) {
		log.info(`Using local interface ${link.ifname} (${link.address}${link.vlan ? `, VLAN ${link.vlan}` : ''})`);

		return proto({
			address: link.address,
			ifname: link.ifname,
			i1905rxsock, i1905txsock,
			lldprxsock, lldptxsock,
			neighbors: []
		}, this);
	},

	addNeighbor: function(i1905if) {
		if (!(i1905if in this.neighbors)) {
			log.debug('Adding new link %s/%s -> %s', this.ifname, this.address, i1905if.address);
			push(this.neighbors, i1905if);
		}

		return i1905if;
	},

	getNeighbors: function() {
		return [ ...this.neighbors ];
	},

	isBridged: function() {
		for (let i1905if in this.neighbors)
			if (i1905if.isBridged())
				return true;

		return false;
	},

	getMediaType: function() {
		let info = this.getRuntimeInformation();

		if (info.type === null) {
			if (info.wifi) {
				info.type = 0x0101; /* default to IEEE 802.11g (2.4 GHz), try refining below */

				for (let band in info.wifi.phy.wiphy_bands) {
					for (let freq in band.freqs) {
						if (freq.freq == info.wifi.interface.center_freq1) {
							if (band.vht_capa) {
								info.type = 0x0105; /* IEEE 802.11ac (5 GHz) */
							}
							else if (band.ht_capa) {
								if (info.wifi.interface.wiphy_freq < 5000)
									info.type = 0x0103; /* IEEE 802.11n (2.4 GHz) */
								else
									info.type = 0x0104; /* IEEE 802.11n (5 GHz) */
							}
							else {
								if (info.wifi.interface.wiphy_freq < 5000)
									info.type = 0x0101; /* IEEE 802.11g (2.4 GHz) */
								else
									info.type = 0x0102; /* IEEE 802.11a (5 GHz) */
							}

							break;
						}
					}
				}
			}
			else {
				if (info.speed >= 1000)
					info.type = 0x0001; /* IEEE 802.3ab gigabit */
				else
					info.type = 0x0000; /* IEEE 802.3u fast Ethernet */
			}
		}

		return info.type;
	},

	getIPAddrs: function(ifstatus) {
		let info = this.getRuntimeInformation();

		if (info.ipaddrs === null) {
			let addrs = rtnl.request(rtnl.const.RTM_GETADDR, rtnl.const.NLM_F_DUMP|rtnl.const.NLM_F_STRICT_CHK, { dev: this.ifname, family: rtnl.const.AF_INET });
			let ifstat;

			for (let s in ifstatus?.interface) {
				if (s?.l3_device == info.ifname) {
					ifstat = s;
					break;
				}
			}

			info.ipaddrs = [];

			for (let addr in addrs) {
				if (addr.family != rtnl.const.AF_INET)
					continue;

				let ip_mask_type_dhcp = split(addr.address, '/');

				ip_mask_type_dhcp[2] = (index(ip_mask_type_dhcp[0], '169.254.') == 0) ? 3 /* Auto-IP */ : 0 /* Unknown */;
				ip_mask_type_dhcp[3] = '0.0.0.0';

				for (let a in ifstat?.['ipv4-address']) {
					if (a == ip_mask_type_dhcp[0]) {
						switch (ifstat.proto) {
						case 'dhcp':
							ip_mask_type_dhcp[2] = 1;
							ip_mask_type_dhcp[3] = ifstat.data?.dhcpserver;
							break;

						case 'static':
							ip_mask_type_dhcp[2] = 2;
							break;
						}
					}
				}

				push(info.ipaddrs, ip_mask_type_dhcp);
			}
		}

		return info.ipaddrs;
	},

	getIP6Addrs: function(ifstatus) {
		let info = this.getRuntimeInformation();

		if (info.ip6addrs === null) {
			let addrs = rtnl.request(rtnl.const.RTM_GETADDR, rtnl.const.NLM_F_DUMP|rtnl.const.NLM_F_STRICT_CHK, { dev: this.ifname, family: rtnl.const.AF_INET6 });
			let ifstat;

			for (let s in ifstatus?.interface) {
				if (s?.l3_device == info.ifname) {
					ifstat = s;
					break;
				}
			}

			info.ip6addrs = [ [ '::', 0, 0, '::' ] ];

			for (let addr in addrs) {
				if (addr.family != rtnl.const.AF_INET6)
					continue;

				// skip expired addresses
				if (addr.cacheinfo?.preferred === 0 || addr.cacheinfo?.valid === 0)
					continue;

				let ip_mask_type_origin = split(addr.address, '/');
				let ip6arr = iptoarr(ip_mask_type_origin[0]);

				ip_mask_type_origin[1] = +ip_mask_type_origin[1];
				ip_mask_type_origin[2] = 0;
				ip_mask_type_origin[3] = '::';

				// link local address
				if (ip6arr[0] == 0xfe && ip6arr[1] >= 0x80 && ip6arr[1] <= 0xbf) {
					info.ip6addrs[0] = ip_mask_type_origin;
					continue;
				}

				// Infer address types
				for (let a in ifstat?.['ipv6-address']) {
					if (a == ip_mask_type_origin[0]) {
						switch (ifstat.proto) {
						case 'dhcpv6':
							if (a.mask == 64)
								ip_mask_type_origin[2] = 3; /* SLAAC */
							else
								ip_mask_type_origin[2] = 1; /* DHCPv6 */

							break;

						case 'static':
							ip_mask_type_origin[2] = 2;
							break;
						}
					}
				}

				// On unavailable ubus state, try to guess SLAAC state */
				if (ip_mask_type_origin[2] == 0 &&
				    addr.cacheinfo.valid < 4294967295 /* address expires */ &&
				    !(addr.flags & rtnl.const.IFA_F_PERMANENT) /* address is not permanent */) {
					if (ip_mask_type_origin[1] == 64)
						ip_mask_type_origin[2] = 3; /* SLAAC */
					else
						ip_mask_type_origin[2] = 1; /* DHCPv6 */
				}

				// Find origin address
				if (ip_mask_type_origin[2] == 1 || ip_mask_type_origin[2] == 3) {
					for (let r in ifstat?.route) {
						let bits = 128 - r.mask;
						let netarr = iptoarr(r.target);
						let match = true;

						for (let i = 16; i > 0; i--) {
							let b = min(bits, 8);
							let m = ~((1 << b) - 1) & 0xff;

							if ((ip6arr[i - 1] & m) != (netarr[i - 1] & m)) {
								match = false;
								break;
							}

							bits -= b;
						}

						// FIXME: naively assume that nexthop == DHCPv6 / RA server
						if (r.nexthop != '::' && match) {
							ip_mask_type_origin[3] = r.nexthop;
							break;
						}
					}
				}

				push(info.ip6addrs, ip_mask_type_origin);
			}
		}

		return info.ip6addrs;
	},

	getRuntimeInformation: function(refresh) {
		if (!refresh && this.info)
			return this.info;

		let link = rtnl.request(rtnl.const.RTM_GETLINK, 0, { dev: this.ifname }),
		    wifi = nl80211.request(nl80211.const.NL80211_CMD_GET_INTERFACE, 0, { dev: this.ifname }),
		    wphy = nl80211.request(nl80211.const.NL80211_CMD_GET_WIPHY, 0, { dev: this.ifname }),
		    wsta = nl80211.request(nl80211.const.NL80211_CMD_GET_STATION, nl80211.const.NLM_F_DUMP, { dev: this.ifname });

		if (!link)
			return null;

		return (this.info = {
			ifname: this.ifname,
			address: link.address,
			statistics: link.stats64,
			bridge: (link.linkinfo?.slave?.type == 'bridge') ? link.master : null,
			speed: +fs.readfile(`/sys/class/net/${this.ifname}/speed`),
			mtu: +fs.readfile(`/sys/class/net/${this.ifname}/mtu`),
			wifi: (wifi && wphy) ? {
				phy: wphy,
				interface: wifi,
				stations: wsta ?? []
			} : null
		});
	},

	getLinkMetrics: function(remote_address) {
		let ifinfo = this.getRuntimeInformation();

		let res = {
			tx_errors: 0,
			tx_packets: 0,
			rx_errors: 0,
			rx_packets: 0,
			rssi: 0xff,
			throughput: 0,
			phyrate: 0xffff,
			availability: 100
		};

		if (ifinfo.wifi) {
			for (let station in ifinfo.wifi.stations) {
				if (station.mac == remote_address) {
					res.tx_errors = station.sta_info?.tx_failed ?? 0;
					res.tx_packets = station.sta_info?.tx_packets ?? 0;
					res.rx_errors = station.sta_info?.rx_failed ?? 0;
					res.rx_packets = station.sta_info?.rx_packets ?? 0;
					res.rssi = (max(-110, min(0, station.sta_info?.signal_avg ?? 0)) + 110) * 2;
					res.throughput = (station.sta_info?.expected_throughput ?? 0) / 1024;
					break;
				}
			}
		}
		else {
			/* Calculate estimated ethernet throughput */
			let framesize = (14 /* header */ + 4 /* crc */ + ifinfo.mtu) * 8,
			    preamble = 8 * 8,
			    framegap = 12 * 8,
			    frames_per_second = (ifinfo.speed * 1000.0) / (framesize + preamble + framegap),
			    total_throughput = frames_per_second * framesize,
			    preamble_overhead = frames_per_second * preamble,
			    interframe_overhead = frames_per_second * framegap;

			res.tx_errors = ifinfo.statistics.tx_errors;
			res.rx_packets = ifinfo.statistics.tx_packets;
			res.rx_errors = ifinfo.statistics.rx_errors;
			res.rx_packets = ifinfo.statistics.rx_packets;
			res.phyrate = ifinfo.speed;
			res.throughput = +sprintf('%.0f', (total_throughput - preamble_overhead - interframe_overhead) / 1000);
		}

		return res;
	},

	collectGarbage: function(now) {
		let changed = 0;

		now ??= timems();

		for (let i = 0; i < length(this.neighbors); ) {
			if (now - this.neighbors[i].seen > 180000) {
				log.debug('Removing stale link %s/%s -> %s', this.ifname, this.address, this.neighbors[i].address);
				changed |= !!splice(this.neighbors, i, 1);
			}
			else {
				changed |= this.neighbors[i++].collectGarbage(now);
			}
		}

		return (changed != 0);
	}
}, I1905Entity);

const I1905Device = proto({
	new: function(al_address) {
		return proto({
			al_address,
			tlvs: {},
			interfaces: [],
			seen: timems()
		}, this);
	},

	updateTLVs: function(tlvs) {
		let updated = false;
		let now = timems();

		for (let tlv in tlvs) {
			switch (tlv?.type) {
			case defs.TLV_DEVICE_INFORMATION:
			case defs.TLV_DEVICE_BRIDGING_CAPABILITY:
			case defs.TLV_NON1905_NEIGHBOR_DEVICES:
			case defs.TLV_IEEE1905_NEIGHBOR_DEVICES:
			case defs.TLV_LINK_METRIC_TX:
			case defs.TLV_LINK_METRIC_RX:
			case defs.TLV_L2_NEIGHBOR_DEVICE:
			case defs.TLV_VENDOR_SPECIFIC:
			case defs.TLV_CONTROL_URL:
			case defs.TLV_IPV4:
			case defs.TLV_IPV6:
			case defs.TLV_1905_PROFILE_VERSION:
			case defs.TLV_DEVICE_IDENTIFICATION:
				if (!this.tlvs[tlv.type]) {
					this.tlvs[tlv.type] = [ now ];
				}
				else if (this.tlvs[tlv.type][0] < now) {
					splice(this.tlvs[tlv.type], 0);
					this.tlvs[tlv.type][0] = now;
				}

				push(this.tlvs[tlv.type], tlv.payload);
				updated = true;
				break;
			}
		}

		if (updated)
			this.update();

		return updated;
	},

	addInterface: function(address) {
		let iface = this.lookupInterface(address);

		if (iface) {
			iface.update();
		}
		else {
			iface = push(this.interfaces, I1905RemoteInterface.new(address, this));
			log.debug('Adding new interface %s to device %s', address, this.al_address);
		}

		return iface;
	},

	lookupInterface: function(address) {
		for (let iface in this.interfaces)
			if (iface.address == address)
				return iface;

		return null;
	},

	getInterfaces: function() {
		return [ ...this.interfaces ];
	},

	isBridged: function() {
		for (let iface in this.interfaces)
			if (iface.isBridged())
				return true;

		return false;
	},

	isIEEE1905: function() {
		let now = timems();

		for (let iface in this.interfaces)
			if (now - iface.seen_cmdu <= 180000)
				return true;

		return false;
	},

	getInterfaceInformation: function() {
		let d = this.tlvs[defs.TLV_DEVICE_INFORMATION]?.[1];
		let interfaces = {};

		for (let iface in tlv.decode(defs.TLV_DEVICE_INFORMATION, d)?.ifaces)
			interfaces[iface.address] ??= iface;

		for (let i1905if in this.interfaces) {
			interfaces[i1905if.address] ??= {
				address: i1905if.address,
				media_type: 0,
				media_type_name: 'Unknown'
			};
		}

		return interfaces;
	},

	getIdentification: function() {
		let d = this.tlvs[defs.TLV_DEVICE_IDENTIFICATION]?.[1];

		if (!d)
			return null;

		return tlv.decode(defs.TLV_DEVICE_IDENTIFICATION, d);
	},

	getLinks: function() {
		let links = {};

		for (let type in [ defs.TLV_LINK_METRIC_RX, defs.TLV_LINK_METRIC_TX ]) {
			for (let i = 1; i < length(this.tlvs[type]); i++) {
				let d = tlv.decode(type, this.tlvs[type][i]);

				for (let link in d?.links) {
					links[link.local_address] ??= {};

					let m = (links[link.local_address][link.remote_address] ??= {
						rx_errors: 0,
						rx_packets: 0,
						tx_errors: 0,
						tx_packets: 0,
						is_bridge: false
					});

					m.media_type ??= link.media_type;
					m.media_type_name ??= link.media_type_name;

					if (type == defs.TLV_LINK_METRIC_RX) {
						m.rx_errors = link.errors;
						m.rx_packets = link.packets;
						m.rssi = link.rssi;
					}
					else {
						m.tx_errors = link.errors;
						m.tx_packets = link.packets;
						m.throughput = link.throughput;
						m.availability = link.availability;
						m.is_bridge = link.is_bridge;
						m.speed = link.speed;
					}
				}
			}
		}

		return links;
	},

	getIPAddrs: function() {
		let interfaces = {};

		for (let type in [ defs.TLV_IPV4, defs.TLV_IPV6 ]) {
			for (let i = 1; i < length(this.tlvs[type]); i++) {
				for (let d in tlv.decode(type, this.tlvs[type][i])) {
					let ifc = (interfaces[d.address] ??= {
						ipaddrs: [],
						ip6addrs: [],
						ip6ll: '::'
					});

					if (d.ip6ll)
						ifc.ip6ll = d.ip6ll;

					if (d.ipaddrs)
						push(ifc.ipaddrs, ...d.ipaddrs);

					if (d.ip6addrs)
						push(ifc.ip6addrs, ...d.ip6addrs);
				}
			}
		}

		return interfaces;
	},

	dumpInformation: function() {
		let res = {};

		for (let type, tlvs in this.tlvs) {
			for (let i = 1; i < length(tlvs); i++) {
				//let neighbor, addresses;
				switch (+type) {
				//case defs.TLV_DEVICE_INFORMATION:
				//	res.info = tlv.decode(+type, tlvs[i]);
				//	break;

				case defs.TLV_IEEE1905_NEIGHBOR_DEVICES:
					let neighbor = tlv.decode(+type, tlvs[i]);
					if (neighbor) {
						res.neighbors ??= {};
						push(res.neighbors.ieee1905 ??= [], neighbor);
					}
					break;

				case defs.TLV_NON1905_NEIGHBOR_DEVICES:
					let addresses = tlv.decode(+type, tlvs[i]);
					if (addresses) {
						res.neighbors ??= {};

						for (let j = 1; j < length(addresses); j++) {
							res.neighbors.others ??= {};
							push(res.neighbors.others[addresses[0]] ??= [], addresses[j]);
						}
					}
					break;

				//case defs.TLV_LINK_METRIC_TX:
				//	res.metrics ??= {};
				//	push(res.metrics.tx ??= [], tlv.decode(+type, tlvs[i]));
				//	break;

				//case defs.TLV_LINK_METRIC_RX:
				//	res.metrics ??= {};
				//	push(res.metrics.rx ??= [], tlv.decode(+type, tlvs[i]));
				//	break;

				case defs.TLV_L2_NEIGHBOR_DEVICE:
					res.l2 = tlv.decode(+type, tlvs[i]);
					break;

				//case defs.TLV_IPV4:
				//	res.ipv4 ??= [];
				//	push(res.ipv4, ...tlv.decode(+type, tlvs[i]));
				//	break;

				//case defs.TLV_IPV6:
				//	res.ipv6 ??= [];
				//	push(res.ipv6, ...tlv.decode(+type, tlvs[i]));
				//	break;
				}
			}
		}

		return res;
	},

	getTLVs: function(...types) {
		let res = [];

		for (let type in types) {
			for (let i, payload in this.tlvs[type]) {
				if (i > 0) {
					push(res, proto({
						type,
						length: length(payload),
						payload
					}, tlv));
				}
			}
		}

		return res;
	},

	collectGarbage: function(now) {
		let changed = 0;

		now ??= timems();

		for (let i = 0; i < length(this.interfaces); ) {
			if (now - this.interfaces[i].seen > 180000) {
				log.debug('Removing stale interface %s from device %s', this.interfaces[i].address, this.al_address);
				changed |= !!splice(this.interfaces, i, 1);
			}
			else {
				i++;
			}
		}

		for (let k, v in this.tlvs)
			if (now - v[0] > 180000)
				changed |= delete this.tlvs[k];

		return (changed != 0);
	}
}, I1905Entity);

return proto({
	address: '00:00:00:00:00:00',
	interfaces: {},
	devices: [],
	topologyChanged: false,
	seen: timems(),

	initializeAddress: function() {
		let mac = 'ff:ff:ff:ff:ff:ff',
		    hash = 5381;

		/* Determine the lowest MAC address among local interfaces... */
		for (let ifname, i1905lif in this.interfaces)
			if (i1905lif.address < mac)
				mac = i1905lif.address;

		/* ... hash its bytes ... */
		mac = struct.unpack('!6B', hexdec(mac, ':'));

		hash = ((hash << 5) + hash) + mac[0];
		hash = ((hash << 5) + hash) + mac[1];
		hash = ((hash << 5) + hash) + mac[2];
		hash = ((hash << 5) + hash) + mac[3];
		hash = ((hash << 5) + hash) + mac[4];
		hash = ((hash << 5) + hash) + mac[5];

		/* ... and turn result into a locally administered MAC */
		this.address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x',
			0x02 | ((hash >> 56) & 0xfe),
			(hash >> 48) & 0xff, (hash >> 40) & 0xff,
			(hash >> 32) & 0xff, (hash >> 24) & 0xff,
			(hash >> 16) & 0xff);

		log.info(`Using AL MAC address: ${this.address}`);
	},

	addLocalInterface: function(ifname) {
		let i1905rxsock = socket.create(ifname, socket.const.ETH_P_1905);
		let lldprxsock = socket.create(ifname, socket.const.ETH_P_LLDP);
		let rv;

		if (!i1905rxsock || !lldprxsock)
			return null;

		for (let link in resolve_bridge_ports(ifname)) {
			let i1905txsock = i1905rxsock;
			let lldptxsock = lldprxsock;

			if (link.ifname != ifname) {
				i1905txsock = socket.create(ifname, socket.const.ETH_P_1905, link.vlan);
				lldptxsock = socket.create(ifname, socket.const.ETH_P_LLDP, link.vlan);

				if (!i1905txsock || !lldptxsock)
					return null;
			}

			rv = (this.interfaces[link.ifname] ??= I1905LocalInterface.new(link, i1905rxsock, i1905txsock, lldprxsock, lldptxsock));
		}

		return rv;
	},

	lookupLocalInterface: function(value) {
		for (let k, ifc in this.interfaces)
			if (ifc.ifname == value || ifc.address == value ||
			    ifc.i1905rxsock == value || ifc.i1905txsock == value ||
			    ifc.lldprxsock == value || ifc.lldptxsock == value)
				return ifc;
	},

	getLocalInterfaces: function() {
		return values(this.interfaces);
	},

	addDevice: function(al_address) {
		let dev = this.lookupDevice(al_address);

		if (dev) {
			dev.update();
		}
		else {
			dev = push(this.devices, I1905Device.new(al_address));
			this.topologyChanged = true;
			log.debug('Adding new neighbor device %s', al_address);
		}

		return dev;
	},

	lookupDevice: function(address) {
		for (let dev in this.devices)
			if (dev.al_address == address || dev.lookupInterface(address))
				return dev;

		return null;
	},

	getLocalDevice: function() {
		return this.devices[0];
	},

	getDevices: function() {
		return [ ...this.devices ];
	},

	updateSelf: function() {
		let i1905dev = this.addDevice(this.address);
		let bridges = {};
		let tlvs = [];

		let i1905neighs = [];
		let i1905macs = [];

		let neightbl = rtnl.request(rtnl.const.RTM_GETNEIGH, rtnl.const.NLM_F_DUMP) ?? [];
		let ifstatus = ubus.call('network.interface', 'dump')?.interface ?? [];

		for (let i1905neigh in this.devices)
			if (i1905neigh.isIEEE1905())
				for (let i1905if in i1905neigh.interfaces)
					push(i1905macs, i1905if.address);

		for (let i1905if in this.getLocalInterfaces()) {
			let info = i1905if.getRuntimeInformation(true);

			if (!info)
				continue;

			let i1905rif = i1905dev.addInterface(info.address);

			i1905rif.updateCMDUTimestamp();
			i1905rif.updateLLDPTimestamp();

			if (info.bridge)
				push(bridges[info.bridge] ??= [], info.address);

			let others, neighs, l2devs;

			if (info.wifi) {
				for (let station in info.wifi.stations) {
					if (!(station.mac in l2devs))
						push(l2devs ??= [], station.mac);

					// Skip known IEEE1905 neighbors
					if (station.mac in i1905macs)
						continue;

					if (!(station.mac in others))
						push(others ??= [], station.mac);
				}
			}
			else {
				for (let neigh in neightbl) {
					if (neigh.dev != info.ifname)
						continue;

					if (neigh.type != rtnl.const.RTN_UNICAST)
						continue;

					if (neigh.state != rtnl.const.NUD_REACHABLE && neigh.state != rtnl.const.NUD_PERMANENT)
						continue;

					if (!(neigh.lladdr in l2devs))
						push(l2devs ??= [], neigh.lladdr);

					if (neigh.lladdr in neighs)
						continue;

					// Skip known IEEE1905 neighbors
					if (neigh.lladdr in i1905macs)
						continue;

					if (!(neigh.lladdr in others))
						push(others ??= [], neigh.lladdr);
				}
			}

			for (let i1905rif in i1905if.neighbors) {
				// Skip non-IEEE1905 neighbors
				if (!i1905rif.dev.isIEEE1905())
					continue;

				push(neighs ??= [], i1905rif);

				if (!(i1905rif.dev in i1905neighs))
					push(i1905neighs ??= [], i1905rif.dev);
			}

			if (neighs)
				push(tlvs, tlv.encode(defs.TLV_IEEE1905_NEIGHBOR_DEVICES, info.address, neighs));

			if (others)
				push(tlvs, tlv.encode(defs.TLV_NON1905_NEIGHBOR_DEVICES, info.address, others));

			if (l2devs)
				push(tlvs, tlv.encode(defs.TLV_L2_NEIGHBOR_DEVICE, info.address, l2devs));
		}

		for (let i1905neigh in i1905neighs) {
			if (!i1905neigh.isIEEE1905())
				continue;

			let links;

			for (let i1905rif in i1905neigh.interfaces) {
				for (let ifname, i1905lif in this.interfaces) {
					if (!(i1905rif in i1905lif.neighbors))
						continue;

					push(links ??= [], i1905lif, i1905rif);
				}
			}

			if (links) {
				push(tlvs,
					tlv.encode(defs.TLV_LINK_METRIC_TX, this.address, i1905neigh.al_address, links),
					tlv.encode(defs.TLV_LINK_METRIC_RX, this.address, i1905neigh.al_address, links)
				);
			}
		}

		let i1905lifs = values(this.interfaces);

		push(tlvs,
			tlv.encode(defs.TLV_IPV4, i1905lifs, ifstatus),
			tlv.encode(defs.TLV_IPV6, i1905lifs, ifstatus),
			tlv.encode(defs.TLV_DEVICE_INFORMATION, i1905lifs),
			tlv.encode(defs.TLV_DEVICE_IDENTIFICATION, null, null, null),
			tlv.encode(defs.TLV_DEVICE_BRIDGING_CAPABILITY, values(bridges)),
			tlv.encode(defs.TLV_CONTROL_URL, 'http://192.168.1.1' /* FIXME */),
			tlv.encode(defs.TLV_1905_PROFILE_VERSION, 0x01)
		);

		for (let i1905rif in i1905dev.interfaces) {
			i1905rif.updateCMDUTimestamp();
			i1905rif.updateLLDPTimestamp();
		}

		i1905dev.updateTLVs(tlvs);
	},

	collectGarbage: function(now) {
		let changed = 0;

		now ??= timems();

		for (let i = 1 /* skip self */; i < length(this.devices); ) {
			if (now - this.devices[i].seen > 180000) {
				log.debug('Removing stale neighbor device %s', this.devices[i].al_address);
				changed |= !!splice(this.devices, i, 1);
			}
			else {
				changed |= this.devices[i++].collectGarbage(now);
			}
		}

		this.topologyChanged ||= (changed != 0);

		return (changed != 0);
	}
}, I1905Entity);
