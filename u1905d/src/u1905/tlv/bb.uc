import { pack } from 'struct';

export default {
	type: 0xbb,
	name: 'BSS Configuration Request',

	schema: {
		type: "string",
		required: true
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 0)
			return null;

		let offset = 0;
		const dpp_configuration_request_object = unpack('*', payload, offset);

		return dpp_configuration_request_object;
	},

	encode: (dpp_configuration_request_object) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(dpp_configuration_request_object) != "string")
			return null;

		push(fmt, "*");
		push(val, dpp_configuration_request_object);

		return pack(join("", fmt), ...val);
	},

};
