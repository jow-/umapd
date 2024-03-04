import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x9c,
	name: 'Steering BTM Report',

	schema: {
		type: "object",
		properties: {
			bssid: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			sta_mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			btm_status_code: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			target_bssid: {
				type: "string",
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 13)
			return null;

		let offset = 0;

		const bssid = utils.ether_ntoa(payload, offset);
		offset += 6;

		const sta_mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const btm_status_code = ord(payload, offset++);

		let target_bssid = null;
		if (offset + 6 <= len) {
			target_bssid = utils.ether_ntoa(payload, offset);
			offset += 6;
		}

		if (offset < len)
			return null;

		return {
			bssid,
			sta_mac_address,
			btm_status_code,
			target_bssid,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		const bssid = utils.ether_aton(tlv.bssid);
		if (bssid == null)
			return null;

		const sta_mac_address = utils.ether_aton(tlv.sta_mac_address);
		if (sta_mac_address == null)
			return null;

		if (type(tlv.btm_status_code) != "int" || tlv.btm_status_code < 0 || tlv.btm_status_code > 0xff)
			return null;

		let target_bssid = null;
		if (tlv.target_bssid != null) {
			target_bssid = utils.ether_aton(tlv.target_bssid);
			if (target_bssid == null)
				return null;
		}

		push(fmt, "6s");
		push(val, bssid);

		push(fmt, "6s");
		push(val, sta_mac_address);

		push(fmt, "B");
		push(val, tlv.btm_status_code);

		if (target_bssid != null) {
			push(fmt, "6s");
			push(val, target_bssid);
		}

		return pack(join("", fmt), ...val);
	},

};
