import { pack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0xda,
	name: 'Spatial Reuse Config Response',

	schema: {
		type: "object",
		properties: {
			radio_unique_identifier: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			response_code: {
				type: "integer",
				required: true,
				enum: [ 0x00, 0x01 ]
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 7)
			return null;

		let offset = 0;

		const radio_unique_identifier = utils.ether_ntoa(payload, offset);
		offset += 6;

		const response_code = ord(payload, offset++);

		if (!exists(defs.RESPONSE_CODE, response_code))
			return null;

		if (offset < len)
			return null;

		return {
			radio_unique_identifier,
			response_code,
			response_code_name: defs.RESPONSE_CODE[response_code],
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		const radio_unique_identifier = utils.ether_aton(tlv.radio_unique_identifier);
		if (radio_unique_identifier == null)
			return null;

		if (!(tlv.response_code in [ 0x00, 0x01 ]))
			return null;

		push(fmt, "6s");
		push(val, radio_unique_identifier);

		push(fmt, "B");
		push(val, tlv.response_code);

		return pack(join("", fmt), ...val);
	},

};
