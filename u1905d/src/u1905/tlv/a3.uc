import { pack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0xa3,
	name: 'Error Code',

	schema: {
		type: "object",
		properties: {
			reason_code: {
				type: "integer",
				required: true,
				enum: [ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 ]
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

		if (len < 7)
			return null;

		let offset = 0;
		const reason_code = ord(payload, offset++);

		if (!exists(defs.REASON_CODE, reason_code))
			return null;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		if (offset < len)
			return null;

		return {
			reason_code,
			reason_code_name: defs.REASON_CODE[reason_code],
			mac_address,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (!(tlv.reason_code in [ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 ]))
			return null;

		const mac_address = utils.ether_aton(tlv.mac_address);
		if (mac_address == null)
			return null;

		push(fmt, "B");
		push(val, tlv.reason_code);

		push(fmt, "6s");
		push(val, mac_address);

		return pack(join("", fmt), ...val);
	},

};
