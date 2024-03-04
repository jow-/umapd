import { pack } from 'struct';
import defs from 'u1905.defs';

export default {
	type: 0x91,
	name: 'Client Capability Report',

	schema: {
		type: "object",
		properties: {
			result_code: {
				type: "integer",
				required: true,
				enum: [ 0x00, 0x01 ]
			},
			frame_body: {
				type: "string",
				required: true
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const result_code = ord(payload, offset++);

		if (!exists(defs.RESULT_CODE, result_code))
			return null;

		const frame_body = unpack('*', payload, offset);

		return {
			result_code,
			result_code_name: defs.RESULT_CODE[result_code],
			frame_body,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (!(tlv.result_code in [ 0x00, 0x01 ]))
			return null;

		if (type(tlv.frame_body) != "string")
			return null;

		push(fmt, "B");
		push(val, tlv.result_code);

		push(fmt, "*");
		push(val, tlv.frame_body);

		return pack(join("", fmt), ...val);
	},

};
