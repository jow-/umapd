import { pack } from 'struct';

export default {
	type: 0xbd,
	name: 'BSS Configuration Response',

	schema: {
		type: "string",
		required: true
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 0)
			return null;

		let offset = 0;
		const dpp_configuration_object = unpack('*', payload, offset);

		return dpp_configuration_object;
	},

	encode: (dpp_configuration_object) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(dpp_configuration_object) != "string")
			return null;

		push(fmt, "*");
		push(val, dpp_configuration_object);

		return pack(join("", fmt), ...val);
	},

};
