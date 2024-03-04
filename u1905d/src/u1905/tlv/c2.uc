import { pack } from 'struct';

export default {
	type: 0xc2,
	name: 'Tunneled',

	schema: {
		type: "string",
		required: true
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 0)
			return null;

		let offset = 0;
		const request_frame_body = unpack('*', payload, offset);

		return request_frame_body;
	},

	encode: (request_frame_body) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(request_frame_body) != "string")
			return null;

		push(fmt, "*");
		push(val, request_frame_body);

		return pack(join("", fmt), ...val);
	},

};
