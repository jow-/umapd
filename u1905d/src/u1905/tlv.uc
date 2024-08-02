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

import { readfile, open } from 'fs';
import { pack, unpack } from 'struct';

import { encoder, decoder, extended_encoder, extended_decoder } from 'u1905.tlv.codec';

import utils from 'u1905.utils';
import defs from 'u1905.defs';
import log from 'u1905.log';


function encode_local_interface(i1905lif) {
	let media_info = "";
	let info = i1905lif.getRuntimeInformation();

	if (!info)
		return null;

	if (info.wifi) {
		let role = 0, chanbw = 0, chan1 = 0, chan2 = 0;

		switch (info.wifi.interface.iftype ?? 0) {
		case 1: /* Ad-Hoc */
		case 2: /* Station */
		case 5: /* WDS */
		case 6: /* Monitor */
		case 7: /* Mesh Point */
		case 10: /* P2P Device */
		case 11: /* OCB */
		case 12: /* NAN */
			role = 0b01000000;
			break;

		case 3: /* AP */
		case 4: /* AP VLAN */
			role = 0b00000000;
			break;

		case 8: /* P2P Client */
			role = 0b10000000;
			break;

		case 9: /* P2P Go */
			role = 0b10010000;
			break;

		default: /* unspecified/unknown */
			role = 0b01000000;
			break;
		}

		switch (info.wifi.interface.channel_width ?? 0) {
		case 0: /* 20MHz NOHT */
		case 1: /* 20MHz */
		case 2: /* 40Mhz */
			chanbw = 0;
			break;

		case 3: /* 80MHz */
			chanbw = 1;
			break;

		case 4: /* 80+80MHz */
			chanbw = 3;
			break;

		case 5: /* 160MHz */
			chanbw = 2;
			break;

		case 6: /* 5MHz */
		case 7: /* 10MHz */
		case 8: /* 1MHz */
		case 9: /* 2MHz */
		case 10: /* 4MHz */
		case 11: /* 8MHz */
		case 12: /* 16MHz */
			chanbw = 0;
			break;
		}

		for (let band in info.wifi.phy.wiphy_bands) {
			for (let i, freq in band?.freqs) {
				if (freq.freq == info.wifi.interface.center_freq1)
					chan1 = i + 1;
				else if (freq.freq == info.wifi.interface.center_freq2)
					chan2 = i + 1;
			}
		}

		media_info = pack('!6sBBBB', hexdec(info.wifi.interface.mac, ':'), role, chanbw, chan1, chan2);
	}

	return pack('!6sHB*', hexdec(info.address, ':'), info.type, length(media_info), media_info);
}

function decode_media_info(media_type, media_info) {
	if ((media_type & 0xff00) == 0x0100) {
		let mi = unpack('!6sBBBB', media_info);

		if (!mi)
			return null;

		return {
			bssid: utils.ether_ntoa(mi[0]),
			role: mi[1],
			role_name: defs.IEEE80211_ROLES[mi[1]] ?? 'Unknown/Reserved',
			bandwidth: mi[2],
			channel1: mi[3],
			channel2: mi[4]
		};
	}

	return null;
}

function skip(start, end) {
	let a = [];

	while (start <= end) {
		push(a, null);
		start++;
	}

	return a;
}

const TLVDecoder = [
	// 0x00 - End of message TLV
	(payload) => '',

	// 0x01 - AL MAC address type TLV
	(payload) => utils.ether_ntoa(payload),

	// 0x02 - MAC address type TLV
	(payload) => utils.ether_ntoa(payload),

	// 0x03 - Device information type TLV
	(payload) => {
		let len = length(payload);

		if (len < 7)
			return null;

		let res = {
			al_address: utils.ether_ntoa(payload),
			ifaces: []
		};

		let num_ifaces = ord(payload, 6);

		for (let i = 0, off = 7; i < num_ifaces && off < len; i++) {
			if (off + 9 > len)
				return null;

			let values = unpack('!HB', payload, off + 6);

			if (off + 9 + values[1] > len)
				return null;

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res.ifaces, {
				address: utils.ether_ntoa(payload, off),
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]]
			});

			if (values[1])
				res.ifaces[-1].media_info =
					decode_media_info(values[0], substr(payload, off + 9, values[1]));

			off += 9 + values[1];
		}

		return res;
	},

	// 0x04 - Device bridging capability TLV
	(payload) => {
		let off = 0,
			res = null,
			n_tuples = ord(payload, off++);

		while (n_tuples > 0) {
			n_tuples--;

			let n_macs = ord(payload, off++);

			if (n_macs > 0) {
				let tuple = [];

				while (n_macs > 0) {
					push(tuple, utils.ether_ntoa(payload, off));
					n_macs--;
					off += 6;
				}

				push(res ??= [], tuple);
			}
		}

		return res;
	},

	// 0x05
	null,

	// 0x06 - Non-1905 neighbor device list TLV
	(payload) => {
		let len = length(payload);

		if (len <= 6 || (len % 6))
			return null;

		let res = [];

		for (let off = 0; off < len; off += 6)
			push(res, utils.ether_ntoa(payload, off));

		return res;
	},

	// 0x07 - 1905.1 neighbor device TLV
	(payload) => {
		let len = length(payload);

		if (len <= 6 || ((len - 6) % 7))
			return null;

		let res = {
			local_address: utils.ether_ntoa(payload),
			neighbors: []
		};

		for (let off = 6; off < len; off += 7) {
			push(res.neighbors, {
				neighbor_al_address: utils.ether_ntoa(payload, off),
				is_bridge: !!(ord(payload, off + 6) & 0b10000000)
			});
		}

		return res;
	},

	// 0x08 - Link metric query TLV
	(payload) => {
		if (length(payload) < 2)
			return null;

		let neigh = ord(payload, 0),
			mac = null,
			off = 1;

		switch (neigh) {
		case 0x00:
			break;

		case 0x01:
			mac = utils.ether_ntoa(payload, off);
			off += 6;
			break;

		default:
			return null;
		}

		switch (ord(payload, off)) {
		case 0x00:
			return { mac, tx: true, rx: false };

		case 0x01:
			return { mac, tx: false, rx: true };

		case 0x02:
			return { mac, tx: true, rx: true };

		default:
			return null;
		}
	},

	// 0x09 - Transmitter link metric TLV
	(payload) => {
		let len = length(payload);

		if (len <= 12 || ((len - 12) % 29))
			return null;

		let res = {
			al_address: utils.ether_ntoa(payload, 0),
			neighbor_al_address: utils.ether_ntoa(payload, 6),
			links: []
		};

		for (let off = 12; off < len; off += 29) {
			let values = unpack('!HBIIHHH', payload, off + 12);

			if (values[1] > 0x01)
				return null;

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res.links, {
				// ifname: ???,  /* FIXME */
				local_address: utils.ether_ntoa(payload, off),
				remote_address: utils.ether_ntoa(payload, off + 6),
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]],
				is_bridge: (values[1] == 0x01),
				errors: values[2],
				packets: values[3],
				throughput: values[4],
				availability: values[5],
				speed: values[6]
			});
		}

		return res;
	},

	// 0x0a - Receiver link metric TLV
	(payload) => {
		let len = length(payload);

		if (len <= 12 || ((len - 12) % 23))
			return null;

		let res = {
			al_address: utils.ether_ntoa(payload, 0),
			neighbor_al_address: utils.ether_ntoa(payload, 6),
			links: []
		};

		for (let off = 12; off < len; off += 23) {
			let values = unpack('!HIIB', payload, off + 12);

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res.links, {
				// ifname: ???,  /* FIXME */
				local_address: utils.ether_ntoa(payload, off),
				remote_address: utils.ether_ntoa(payload, off + 6),
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]],
				errors: values[1],
				packets: values[2],
				rssi: values[3]
			});
		}

		return res;
	},

	// 0x0b - Vendor specific TLV
	(payload) => payload,

	// 0x0c - Link metric result code TLV
	(payload) => {
		if (length(payload) != 1)
			return null;

		let code = ord(payload, 0);
		let code_name = defs.LINK_METRIC_RESULT_CODES[code];

		return code_name ? { code, code_name } : null;
	},

	// 0x0d - SearchedRole TLV
	(payload) => {
		if (length(payload) != 1)
			return null;

		let role = ord(payload, 0);
		let role_name = defs.SEARCHED_ROLES[role];

		return role_name ? { role, role_name } : null;
	},

	// 0x0e - AutoconfigFreqBand TLV
	(payload) => {
		if (length(payload) != 1)
			return null;

		let band = ord(payload, 0);
		let band_name = defs.IEEE80211_BANDS[band];

		return band_name ? { band, band_name } : null;
	},

	// 0x0f - SupportedRole TLV
	(payload) => {
		if (length(payload) != 1)
			return null;

		let role = ord(payload, 0);
		let role_name = defs.SEARCHED_ROLES[role];

		return role_name ? { role, role_name } : null;
	},

	// 0x10 - SupportedFreqBand TLV
	(payload) => {
		if (length(payload) != 1)
			return null;

		let band = ord(payload, 0);
		let band_name = defs.IEEE80211_BANDS[band];

		return band_name ? { band, band_name } : null;
	},

	// 0x11 - WSC TLV
	(payload) => payload,

	// 0x12 - Push_Button_Event notification TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_types = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; i < num_types && off < len; i++) {
			if (off + 3 > len)
				return null;

			let values = unpack('!HB', payload, off);

			if (off + 3 + values[1] > len)
				return null;

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res, {
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]]
			});

			if (values[1])
				res[-1].media_info =
					decode_media_info(values[0], substr(payload, off + 3, values[1]));

			off += 3 + values[1];
		}

		return res;
	},

	// 0x13 - Push_Button_Join notification TLV
	(payload) => {
		if (length(payload) != 20)
			return null;

		return {
			al_address: utils.ether_ntoa(payload, 0),
			mid: ord(payload, 6) * 256 + ord(payload, 7),
			local_address: utils.ether_ntoa(payload, 8),
			remote_address: utils.ether_ntoa(payload, 14)
		};
	},

	// 0x14 - Generic Phy device information type TLV
	(payload) => {
		let len = length(payload);

		if (len <= 7)
			return null;

		let res = {
			al_address: utils.ether_ntoa(payload, 0),
			links: []
		};

		let num_ifaces = ord(payload, 6);

		for (let off = 7, i = 0; off < len && i < num_ifaces; off += 44, i++) {
			if (off + 44 > len)
				return null;

			let url_len = ord(payload, off + 42);
			let info_len = ord(payload, off + 43);

			if (off + 44 + url_len + info_len > len)
				return null;

			push(res.links, {
				local_address: utils.ether_ntoa(payload, off),
				oui: sprintf('%02x:%02x:%02x', ...unpack(payload, '!3B', off + 6)),
				variant_index: ord(payload, off + 9),
				variant_name: trim(substr(payload, off + 10, 32)),
				xml_description_url: substr(payload, off + 44, url_len),
				media_info: substr(payload, off + 44 + url_len, info_len)
			});
		}

		return res;
	},

	// 0x15 - Device identification type TLV
	(payload) => {
		if (length(payload) != 192)
			return null;

		return {
			friendly_name: trim(substr(payload, 0, 64)),
			manufacturer_name: trim(substr(payload, 64, 64)),
			manufacturer_model: trim(substr(payload, 128, 64))
		};
	},

	// 0x16 - Control URL type TLV
	(payload) => payload,

	// 0x17 - IPv4 type TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_ifaces = ord(payload, 0);
		let res = [];

		for (let off = 1, i = 0; off < len && i < num_ifaces; i++) {
			if (off + 7 > len)
				return null;

			let address = utils.ether_ntoa(payload, off);
			let num_addrs = ord(payload, off + 6);

			off += 7;

			if (off + num_addrs * 9 > len)
				return null;

			let entry = {
				address,
				ipaddrs: []
			};

			for (let j = 0; j < num_addrs; off += 9, j++) {
				push(entry.ipaddrs, {
					type: ord(payload, off),
					type_name: defs.IPV4ADDR_TYPES[ord(payload, off)] ?? 'Reserved',
					ipaddr: arrtoip(unpack('!4B', payload, off + 1)),
					dhcpaddr: arrtoip(unpack('!4B', payload, off + 5))
				});
			}

			push(res, entry);
		}

		return res;
	},

	// 0x18 - IPv6 type TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_ifaces = ord(payload, 0);
		let res;

		for (let off = 1, i = 0; off < len && i < num_ifaces; i++) {
			if (off + 23 > len)
				return null;

			let address = utils.ether_ntoa(payload, off);
			let ip6ll = arrtoip(unpack('!16B', payload, off + 6));
			let num_addrs = ord(payload, off + 22);

			off += 23;

			if (off + num_addrs * 33 > len)
				return null;

			let entry = {
				address,
				ip6ll,
				ip6addrs: []
			};

			for (let j = 0; j < num_addrs; off += 33, j++) {
				push(entry.ip6addrs, {
					type: ord(payload, off),
					type_name: defs.IPV6ADDR_TYPES[ord(payload, off)] ?? 'Reserved',
					ip6addr: arrtoip(unpack('!16B', payload, off + 1)),
					originaddr: arrtoip(unpack('!16B', payload, off + 17))
				});
			}

			push(res ??= [], entry);
		}

		return res;
	},

	// 0x19 - Push_Button_Generic_Phy_Event notification TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_types = ord(payload, 0);

		if (num_types < 1)
			return null;

		let res = [];

		for (let i = 0, off = 1; off < len && i < num_types; i++) {
			if (off + 5 > len)
				return null;

			let info_len = ord(payload, off + 4);

			if (off + 5 + info_len > len)
				return null;

			push(res, {
				oui: sprintf('%02x:%02x:%02x', ...unpack('!3B', payload, off)),
				variant_index: ord(payload, off + 3)
			});

			if (info_len)
				res[-1].media_info = substr(payload, off + 5, info_len);

			off += 5 + info_len;
		}

		return res;
	},

	// 0x1a - 1905 profile version TLV
	(payload) => {
		if (length(payload) != 1)
			return null;

		let version = ord(payload, 0);
		let version_name = defs.IEEE1905_PROFILE_VERSIONS[version];

		return version_name ? { version, version_name } : null;
	},

	// 0x1b - Power off interface TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_ifaces = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; off < len && i < num_ifaces; i++) {
			if (off + 13 > len)
				return null;

			let info_len = ord(payload, off + 13);

			if (off + 13 + info_len > len)
				return null;

			let values = unpack('!H3BB', payload, off + 6);

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res, {
				local_address: utils.ether_ntoa(payload, off),
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]],
				oui: sprintf('%02x:%02x:%02x', values[1], values[2], values[3]),
				variant_index: values[4]
			});

			if (info_len)
				res[-1].media_info = substr(payload, off + 13, info_len);

			off += 13 + info_len;
		}

		return res;
	},

	// 0x1c - Interface power change information TLV
	(payload) => {
		let len = length(payload);

		if (len < 1 || ((len - 1) % 7))
			return null;

		let num_ifaces = ord(payload, 0);

		if (1 + num_ifaces * 7 != len)
			return null;

		let res = [];

		for (let off = 1; off < len; off += 7) {
			let power_state = ord(payload, off + 6);
			let power_state_name = defs.POWER_STATES[power_state];

			if (!power_state_name)
				return null;

			push(res, {
				local_address: utils.ether_ntoa(payload, off),
				power_state, power_state_name
			});
		}

		return res;
	},

	// 0x1d - Interface power change status TLV
	(payload) => {
		let len = length(payload);

		if (len < 1 || ((len - 1) % 7))
			return null;

		let num_ifaces = ord(payload, 0);

		if (1 + num_ifaces * 7 != len)
			return null;

		let res = [];

		for (let off = 1; off < len; off += 7) {
			let change_status = ord(payload, off + 6);
			let change_status_name = defs.POWER_CHANGE_RESULT_CODES[change_status];

			if (!change_status_name)
				return null;

			push(res, {
				local_address: utils.ether_ntoa(payload, off),
				change_status, change_status_name
			});
		}

		return res;
	},

	// 0x1e - L2 neighbor device TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_ifaces = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; i < num_ifaces && off < len; i++) {
			if (off + 8 > len)
				return null;

			let num_neigh = unpack('!H', payload, off + 6)[0];

			push(res, {
				local_address: utils.ether_ntoa(payload, off),
				neighbor_devices: []
			});

			off += 8;

			for (let j = 0; j < num_neigh; j++) {
				if (off + 8 > len)
					return null;

				let num_addrs = unpack('!H', payload, off + 6)[0];

				push(res[-1].neighbor_devices, {
					remote_address: utils.ether_ntoa(payload, off),
					behind_addresses: []
				});

				off += 8;

				if (off + num_addrs * 6 > len)
					return null;

				for (let k = 0; k < num_addrs; k++, off += 6)
					push(res[-1].neighbor_devices[-1].behind_addresses, utils.ether_ntoa(payload, off));
			}
		}

		return res;
	},

	// 0x1f..0x7f - unassigned
	...skip(0x1f, 0x7f),

	// 0x80 - SupportedService TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let res = [];

		for (let off = 0; off < len; off++) {
			let supported_service = ord(payload, off);
			let supported_service_name = defs.SUPPORTED_SERVICES[supported_service];

			if (!supported_service_name)
				return null;

			push(res, {
				supported_service,
				supported_service_name
			});
		}

		return res;
	},

	// 0x81 - SearchedService TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let res = [];

		for (let off = 0; off < len; off++) {
			let searched_service = ord(payload, off);
			let searched_service_name = defs.SEARCHED_SERVICES[searched_service];

			if (!searched_service_name)
				return null;

			push(res, {
				searched_service,
				searched_service_name
			});
		}

		return res;
	},

	// 0x82 - AP Radio Identifier TLV
	(payload) => payload,

	// 0x83 - AP OPerational BSS TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_radios = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; i < num_radios && off < len; i++) {
			if (off + 7 > len)
				return null;

			let radio_unique_id = utils.ether_ntoa(payload, off);
			let num_bsses = ord(payload, off + 6);

			off += 7;

			push(res, {
				radio_unique_id,
				bsses: []
			});

			for (let j = 0; j < num_bsses; j++) {
				if (off + 7 > len)
					return null;

				let bssid = utils.ether_ntoa(payload, off);
				let ssid_len = ord(payload, off + 6);

				off += 7;

				if (off + ssid_len > len)
					return null;

				let ssid = substr(payload, off, ssid_len);

				off += ssid_len;

				push(res[-1].bsses, {
					bssid,
					ssid
				});
			}
		}

		return res;
	},

	// 0x84 - Associated Clients TLV
	(payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_bsses = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; i < num_bsses && off < len; i++) {
			if (off + 8 > len)
				return null;

			let bssid = utils.ether_ntoa(payload, off);
			let num_associated = unpack('!H', payload, off + 6)[0];

			off += 8;

			push(res, {
				bssid,
				clients: []
			});

			for (let j = 0; j < num_associated; j++) {
				if (off + 8 > len)
					return null;

				let mac = utils.ether_ntoa(payload, off);
				let last_seen = unpack('!H', payload, off + 6)[0];

				off += 8;

				push(res[-1].clients, {
					mac,
					last_seen
				});
			}
		}

		return res;
	},

	// 0x85..0x93 - unassigned
	...skip(0x85, 0x93),

	// 0x94 - AP Metrics TLV
	(payload) => {
		let len = length(payload);

		if (len < 10)
			return null;

		let res = {
			bssid: utils.ether_ntoa(payload, 0),
			channel_utilization: ord(payload, 6),
			num_associated: unpack('!H', payload, 7)[0],
			esp_information: []
		};

		let off = 9;
		let have_espinfo = ord(payload, off++);

		for (let i = 0; i < 4 && off < len; i++) {
			if (off + 3 > len)
				return null;

			let values = unpack('!BBB', payload, off);

			off += 3;

			push(res.esp_information, {
				access_category: values[2] & 0x03,
				data_format: (values[2] & 0x18) >> 3,
				ba_window_size: (values[2] & 0xe0) >> 5,
				data_ppdu_duration_target: values[0],
				estimated_air_time_fraction: values[1]
			});
		}

		return res;
	},

	// 0x95..0xb2 - unassigned
	...skip(0x95, 0xb2),

	// 0xb3 - Multi-AP Profile
	(payload) => {
		if (length(payload) != 1)
			return null;

		let profile = ord(payload, 0);
		let profile_name = defs.MULTI_AP_PROFILES[profile];

		return profile_name ? { profile, profile_name } : null;
	},

	// 0xb4 - Profile-2 AP Capability
	(payload) => {
		let len = length(payload);

		if (len < 4)
			return null;

		let flags = ord(payload, 2);
		let unit = (flags >> 6) & 0b11;
		let unit_name = defs.PROFILE_2_BYTE_COUNTER_UNIT[unit];

		if (!unit_name)
			return null;

		return {
			max_priorization_rules: ord(payload, 0),
			max_unique_vids: ord(payload, 3),
			byte_counter_unit: unit,
			byte_counter_unit_name: unit_name,
			supports_traffic_separation: !!(flags & 0b00001000),
			supports_dpp_onboarding: !!(flags & 0b00010000),
			supports_priorization: !!(flags & 0b00100000),
		};
	}
];

const TLVEncoder = [
	// 0x00 - End of message TLV
	() => '',

	// 0x01 - AL MAC address type TLV
	(mac) => pack('!6s', hexdec(mac, ':') ?? ''),

	// 0x02 - MAC address type TLV
	(mac) => pack('!6s', hexdec(mac, ':') ?? ''),

	// 0x03 - Device information type TLV
	(links, al_address) => {
		assert(length(links) <= 255, 'Too many interfaces for TLV');

		if (!length(links))
			return null;

		let fmt = '!6sB';
		let val = [ hexdec(al_address, ':'), 0 ];

		for (let i1905lif in links) {
			val[1]++;
			fmt += '*';
			push(val, encode_local_interface(i1905lif));
		}

		return pack(fmt, ...val);
	},

	// 0x04 - Device bridging capability TLV
	(tuples) => {
		if (length(tuples) == 0 || length(tuples) > 255)
			return null;

		let fmt = '!B',
			val = [ length(tuples) ];

		for (let tuple in tuples) {
			if (length(tuple) == 0)
				continue;

			if (length(tuple) > 255)
				return null;

			fmt += 'B';
			push(val, length(tuple));

			for (let mac in tuple) {
				fmt += '6s';
				push(val, hexdec(mac, ':'));
			}
		}

		return pack(fmt, ...val);
	},

	// 0x05
	null,

	// 0x06 - Non-1905 neighbor device list TLV
	(local_address, remote_addresses) => {
		let fmt = '!6s',
			val = [ hexdec(local_address, ':') ];

		for (let addr in remote_addresses) {
			fmt += '6s';
			push(val, hexdec(addr, ':'));
		}

		return pack(fmt, ...val);
	},

	// 0x07 - 1905.1 neighbor device TLV
	(local_address, links) => {
		let fmt = '!6s',
			val = [ hexdec(local_address, ':') ];

		for (let i1905rif in links) {
			fmt += '6sB';
			push(val,
				hexdec(i1905rif.getDevice().al_address, ':'),
				i1905rif.isBridged() ? 0b10000000 : 0);
		}

		return pack(fmt, ...val);
	},

	// 0x08 - Link metric query TLV
	(address, rx, tx) => {
		let metrics;

		if (rx && tx)
			metrics = 0x02;
		else if (rx)
			metrics = 0x01;
		else /* if (tx) */
			metrics = 0x00;

		return pack('!B*B',
			address ? 0x01 : 0x00,
			address ? hexdec(address, ':') : '',
			metrics
		);
	},

	// 0x09 - Transmitter link metric TLV
	(al_address, neighbor_al_address, links) => {
		let fmt = '!6s6s',
			val = [ hexdec(al_address, ':'), hexdec(neighbor_al_address, ':') ];

		for (let i = 0; i < length(links); i += 2) {
			let i1905lif = links[i + 0],
			    i1905rif = links[i + 1],
			    metrics = i1905lif.getLinkMetrics(i1905rif.address);

			fmt += '6s6sHBIIHHH';
			push(val,
				hexdec(i1905lif.address, ':'),
				hexdec(i1905rif.address, ':'),
				i1905lif.getMediaType(),
				i1905rif.isBridged() ? 0x01 : 0x00,
				metrics.tx_errors,
				metrics.tx_packets,
				metrics.throughput,
				metrics.availability,
				metrics.phyrate
			);
		}

		return pack(fmt, ...val);
	},

	// 0x0a - Receiver link metric TLV
	(al_address, neighbor_al_address, links) => {
		let fmt = '!6s6s',
		    val = [ hexdec(al_address, ':'), hexdec(neighbor_al_address, ':') ];

		for (let i = 0; i < length(links); i += 2) {
			let i1905lif = links[i + 0],
			    i1905rif = links[i + 1],
			    metrics = i1905lif.getLinkMetrics(i1905rif.address);

			fmt += '6s6sHIIB';
			push(val,
				hexdec(i1905lif.address, ':'),
				hexdec(i1905rif.address, ':'),
				i1905lif.getMediaType(),
				metrics.rx_errors,
				metrics.rx_packets,
				metrics.rssi);
		}

		return pack(fmt, ...val);
	},

	// 0x0b - Vendor specific TLV
	(data) => data,

	// 0x0c - Link metric result code TLV
	(code) => pack('!B', code),

	// 0x0d - SearchedRole TLV
	(role) => pack('!B', role),

	// 0x0e - AutoconfigFreqBand TLV
	(band) => pack('!B', band),

	// 0x0f - SupportedRole TLV
	(role) => pack('!B', role),

	// 0x10 - SupportedFreqBand TLV
	(band) => pack('!B', band),

	// 0x11 - WSC TLV
	null,

	// 0x12 - Push_Button_Event notification TLV
	null,

	// 0x13 - Push_Button_Join notification TLV
	null,

	// 0x14 - Generic Phy device information type TLV
	(al_address, ...ifnames) => {
		if (length(ifnames))
			die('Generic phy description not implemented');

		return pack('!6sB',
			hexdec(al_address, ':'),
			length(ifnames));
	},

	// 0x15 - Device identification type TLV
	(friendly_name, manufacturer_name, manufacturer_model) => {
		friendly_name ??= trim(readfile('/proc/sys/kernel/hostname'));

		let osrel = open('/etc/os-release', 'r');
		if (osrel) {
			for (let line = osrel.read('line'); length(line); line = osrel.read('line')) {
				let kv = match(line, '^([^=]+)="(.+)"\n?$');

				switch (kv?.[0]) {
				case 'OPENWRT_DEVICE_MANUFACTURER':
					manufacturer_name ??= kv[1];
					break;

				case 'OPENWRT_DEVICE_PRODUCT':
					manufacturer_model ??= kv[1];
					break;
				}
			}

			osrel.close();
		}

		if (manufacturer_model == null || manufacturer_model == 'Generic')
			manufacturer_model = trim(readfile('/tmp/sysinfo/model'));

		return pack('!63sx63sx63sx',
			friendly_name ?? 'Unknown',
			manufacturer_name ?? 'Unknown',
			manufacturer_model ?? 'Unknown'
		);
	},

	// 0x16 - Control URL type TLV
	(url) => url,

	// 0x17 - IPv4 type TLV
	(links, ifstatus) => {
		assert(length(links) <= 255, 'Too many interfaces for TLV');

		let fmt = '!B';
		let val = [ 0 ];

		for (let i1905lif in links) {
			let ipaddrs = i1905lif.getIPAddrs(ifstatus);

			if (!length(ipaddrs))
				continue;

			val[0]++;
			fmt += '6sB';
			push(val, hexdec(i1905lif.address, ':'), length(ipaddrs));

			for (let i, addr in ipaddrs) {
				if (i >= 16)
					break;

				fmt += 'B4B4B';
				push(val, addr[2], ...iptoarr(addr[0]), ...iptoarr(addr[3]));
			}
		}

		return pack(fmt, ...val);
	},

	// 0x18 - IPv6 type TLV
	(links, ifstatus) => {
		assert(length(links) <= 255, 'Too many interfaces for TLV');

		let fmt = '!B';
		let val = [ 0 ];

		for (let i1905lif in links) {
			let ip6addrs = i1905lif.getIP6Addrs(ifstatus);

			if (!length(ip6addrs))
				continue;

			val[0]++;
			fmt += '6s16BB';
			push(val, hexdec(i1905lif.address, ':'), ...iptoarr(ip6addrs[0][0]), length(ip6addrs) - 1);

			for (let i, addr in ip6addrs) {
				if (i == 0)
					continue;

				if (i >= 17)
					break;

				fmt += 'B16B16B';
				push(val, addr[2], ...iptoarr(addr[0]), ...iptoarr(addr[3] ?? '::'));
			}
		}

		return pack(fmt, ...val);
	},

	// 0x19 - Push_Button_Generic_Phy_Event notification TLV
	null,

	// 0x1a - 1905 profile version TLV
	(version) => pack('!B', version),

	// 0x1b - Power off interface TLV
	null,

	// 0x1c - Interface power change information TLV
	null,

	// 0x1d - Interface power change status TLV
	null,

	// 0x1e - L2 neighbor device TLV
	(local_address, remote_addresses) => {
		let localInterface = {
			if_mac_address: local_address,
			neighbors: map(remote_addresses, mac => {
				let data;

				let neighbor_device = {
					neighbor_mac_address: mac,
					behind_mac_addresses: []
				};

				for (let i1905dev in this.getDevices()) {
					let i1905rif = i1905dev.lookupInterface(mac);

					if (!i1905rif)
						continue;

					let l2 = i1905dev.getTLVs(defs.TLV_L2_NEIGHBOR_DEVICE);

					if (length(l2)) {
						for (let tlv in l2) {
							if ((data = decode_tlv(tlv.type, tlv.payload)) != null) {
								for (let dev in data) {
									if (dev.if_mac_address == mac)
										continue;

									for (let ndev in dev.neighbors) {
										push(neighbor_device.behind_mac_addresses, ndev.neighbor_mac_address);
									}
								}
							}
						}
					}
					else {
						let others = i1905dev.getTLVs(defs.TLV_NON_IEEE1905_NEIGHBOR_DEVICES);
						let metrics = i1905dev.getTLVs(defs.TLV_IEEE1905_RECEIVER_LINK_METRIC);

						for (let tlv in others) {
							if ((data = decode_tlv(tlv.type, tlv.payload)) != null && data.local_if_mac_address != mac)
								push(neighbor_device.behind_mac_addresses, ...data.non_ieee1905_neighbors);
						}

						for (let tlv in metrics) {
							if ((data = decode_tlv(tlv.type, tlv.payload)) != null) {
								for (let link in decode_tlv(tlv.type, tlv.payload).link_metrics) {
									if (link.local_if_mac_address != mac)
										push(neighbor_device.behind_mac_addresses, link.remote_if_mac_address);
								}
							}
						}
					}
				}

				return neighbor_device;
			})
		};

		let data;

		for (let i, mac in remote_addresses) {
			if (i > 255)
				break;

			let neighbor_device = {
				neighbor_mac_address: mac,
				behind_mac_addresses: []
			};

			push(localInterface.neighbors, neighbor_device);

			for (let i1905dev in this.getDevices()) {
				let i1905rif = i1905dev.lookupInterface(mac);

				if (!i1905rif)
					continue;

				let l2 = i1905dev.getTLVs(defs.TLV_L2_NEIGHBOR_DEVICE);

				if (length(l2)) {
					for (let tlv in l2) {
						if ((data = decode_tlv(tlv.type, tlv.payload)) != null) {
							for (let dev in data) {
								if (dev.if_mac_address == mac)
									continue;

								for (let ndev in dev.neighbors) {
									push(neighbor_device.behind_mac_addresses, ndev.neighbor_mac_address);
								}
							}
						}
					}
				}
				else {
					let others = i1905dev.getTLVs(defs.TLV_NON_IEEE1905_NEIGHBOR_DEVICES);
					let metrics = i1905dev.getTLVs(defs.TLV_IEEE1905_RECEIVER_LINK_METRIC);

					for (let tlv in others) {
						if ((data = decode_tlv(tlv.type, tlv.payload)) != null && data.local_if_mac_address != mac)
							push(neighbor_device.behind_mac_addresses, ...data.non_ieee1905_neighbors);
					}

					for (let tlv in metrics) {
						if ((data = decode_tlv(tlv.type, tlv.payload)) != null) {
							for (let link in decode_tlv(tlv.type, tlv.payload).link_metrics) {
								if (link.local_if_mac_address != mac)
									push(neighbor_device.behind_mac_addresses, link.remote_if_mac_address);
							}
						}
					}
				}
			}
		}

		return localInterface;
	}
];

export default {
	create: function(type, payload) {
		if (type < 0 || type > 0xff || length(payload) > 0xffff)
			return null;

		return proto({
			type,
			length: length(payload) ?? 0,
			payload
		}, this);
	},

	parse: function(buf) {
		let tlv_type = buf.get('B');
		let tlv_len = buf.get('!H');

		if (tlv_type === null || tlv_len === null || buf.pos() + tlv_len > buf.length())
			return null;

		return proto({
			type: tlv_type,
			length: tlv_len,
			payload: buf.get(tlv_len)
		}, this);
	},

	decode: function(type, payload) {
		type ??= this.type;
		payload ??= this.payload;

		if (type === defs.TLV_EXTENDED)
			return extended_decoder[unpack('!H', payload)]?.(payload);

		return decoder[type]?.(payload);
	},

	encode: function(type, ...args) {
		let buf = buffer();

		if (type === defs.TLV_EXTENDED) {
			let subtype = shift(args);

			buf.put('!H', subtype);
			buf = extended_encoder[subtype]?.(buf, ...args);
		}
		else {
			buf = encoder[type]?.(buf, ...args);
		}

		if (buf == null)
			return null;

		return proto({
			type,
			length: buf.length(),
			payload: buf.slice()
		}, this);
	}
};
