import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xae,
	name: 'CAC Termination',

	schema: {
		type: "array",
		required: true,
		items: {
			type: "object",
			properties: {
				radio_unique_identifier: {
					type: "string",
					required: true,
					pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
				},
				opclass: {
					type: "integer",
					required: true,
					minimum: 0,
					maximum: 255
				},
				channel: {
					type: "integer",
					required: true,
					minimum: 0,
					maximum: 255
				}
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const radios_count = ord(payload, offset++);

		const radios = [];
		for (let i = 0; i < radios_count; i++) {
			if (offset + 8 >= len)
				return null;

			const radio_unique_identifier = utils.ether_ntoa(payload, offset);
			offset += 6;

			const opclass = ord(payload, offset++);
			const channel = ord(payload, offset++);

			push(radios, {
				radio_unique_identifier,
				opclass,
				channel,
			});
		}

		if (offset < len)
			return null;

		return radios;
	},

	encode: (radios) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(radios) != "array" || length(radios) > 0xff)
			return null;

		push(fmt, "B");
		push(val, length(radios));

		for (let item in radios) {
			if (type(item) != "object")
				return null;

			const radio_unique_identifier = utils.ether_aton(item.radio_unique_identifier);
			if (radio_unique_identifier == null)
				return null;

			if (type(item.opclass) != "int" || item.opclass < 0 || item.opclass > 0xff)
				return null;

			if (type(item.channel) != "int" || item.channel < 0 || item.channel > 0xff)
				return null;

			push(fmt, "6s");
			push(val, radio_unique_identifier);

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "B");
			push(val, item.channel);

		}

		return pack(join("", fmt), ...val);
	},

};
