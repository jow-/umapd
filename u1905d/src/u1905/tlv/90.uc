import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x90,
	name: 'Client Info',

	schema: {
		type: "object",
		properties: {
			bssid: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 12)
			return null;

		let offset = 0;

		const bssid = utils.ether_ntoa(payload, offset);
		offset += 6;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		if (offset < len)
			return null;

		return {
			bssid,
			mac_address,
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

		const mac_address = utils.ether_aton(tlv.mac_address);
		if (mac_address == null)
			return null;

		push(fmt, "6s");
		push(val, bssid);

		push(fmt, "6s");
		push(val, mac_address);

		return pack(join("", fmt), ...val);
	},

};
