import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x8f,
	name: 'Operating Channel Report',

	schema: {
		type: "object",
		properties: {
			radio_unique_identifier: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			current_opclass: {
				type: "array",
				required: true,
				items: {
					type: "object",
					properties: {
						opclass: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						current_operating_channel_number: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						}
					}
				}
			},
			current_transmit_power_eirp: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 8)
			return null;

		let offset = 0;

		const radio_unique_identifier = utils.ether_ntoa(payload, offset);
		offset += 6;

		const current_opclass_count = ord(payload, offset++);

		const current_opclass = [];
		for (let i = 0; i < current_opclass_count; i++) {
			if (offset + 2 >= len)
				return null;

			const opclass = ord(payload, offset++);
			const current_operating_channel_number = ord(payload, offset++);

			push(current_opclass, {
				opclass,
				current_operating_channel_number,
			});
		}

		const current_transmit_power_eirp = ord(payload, offset++);

		if (offset < len)
			return null;

		return {
			radio_unique_identifier,
			current_opclass,
			current_transmit_power_eirp,
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

		if (type(tlv.current_opclass) != "array" || length(tlv.current_opclass) > 0xff)
			return null;

		if (type(tlv.current_transmit_power_eirp) != "int" || tlv.current_transmit_power_eirp < 0 || tlv.current_transmit_power_eirp > 0xff)
			return null;

		push(fmt, "6s");
		push(val, radio_unique_identifier);

		push(fmt, "B");
		push(val, length(tlv.current_opclass));

		for (let item in tlv.current_opclass) {
			if (type(item) != "object")
				return null;

			if (type(item.opclass) != "int" || item.opclass < 0 || item.opclass > 0xff)
				return null;

			if (type(item.current_operating_channel_number) != "int" || item.current_operating_channel_number < 0 || item.current_operating_channel_number > 0xff)
				return null;

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "B");
			push(val, item.current_operating_channel_number);

		}

		push(fmt, "B");
		push(val, tlv.current_transmit_power_eirp);

		return pack(join("", fmt), ...val);
	},

};
