import { pack } from 'struct';

export default {
	type: 0xd1,
	name: 'DPP Message',

	schema: {
		type: "string",
		required: true
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 0)
			return null;

		let offset = 0;
		const dpp_frame = unpack('*', payload, offset);

		return dpp_frame;
	},

	encode: (dpp_frame) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(dpp_frame) != "string")
			return null;

		push(fmt, "*");
		push(val, dpp_frame);

		return pack(join("", fmt), ...val);
	},

};
