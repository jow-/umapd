import { pack } from 'struct';
import defs from 'u1905.defs';

export default {
	type: 0xc1,
	name: 'Tunneled message type',

	schema: {
		type: "integer",
		required: true,
		enum: [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 ]
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const tunneled_protocol_type = ord(payload, offset++);

		if (!exists(defs.TUNNELED_PROTOCOL_TYPE, tunneled_protocol_type))
			return null;

		if (offset < len)
			return null;

		return {
			tunneled_protocol_type,
			tunneled_protocol_type_name: defs.TUNNELED_PROTOCOL_TYPE[tunneled_protocol_type],
		};
	},

	encode: (tunneled_protocol_type) => {
		const fmt = [ "!" ];
		const val = [];

		if (!(tunneled_protocol_type in [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 ]))
			return null;

		push(fmt, "B");
		push(val, tunneled_protocol_type);

		return pack(join("", fmt), ...val);
	},

};
