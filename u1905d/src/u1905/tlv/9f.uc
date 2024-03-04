import { pack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x9f,
	name: 'Backhaul Steering Response',

	schema: {
		type: "object",
		properties: {
			mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			bssid: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			result_code: {
				type: "integer",
				required: true,
				enum: [ 0x00, 0x01 ]
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 13)
			return null;

		let offset = 0;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bssid = utils.ether_ntoa(payload, offset);
		offset += 6;

		const result_code = ord(payload, offset++);

		if (!exists(defs.RESULT_CODE, result_code))
			return null;

		if (offset < len)
			return null;

		return {
			mac_address,
			bssid,
			result_code,
			result_code_name: defs.RESULT_CODE[result_code],
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		const mac_address = utils.ether_aton(tlv.mac_address);
		if (mac_address == null)
			return null;

		const bssid = utils.ether_aton(tlv.bssid);
		if (bssid == null)
			return null;

		if (!(tlv.result_code in [ 0x00, 0x01 ]))
			return null;

		push(fmt, "6s");
		push(val, mac_address);

		push(fmt, "6s");
		push(val, bssid);

		push(fmt, "B");
		push(val, tlv.result_code);

		return pack(join("", fmt), ...val);
	},

};
