import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x8b,
	name: 'Channel Preference',

	schema: {
		type: "object",
		properties: {
			radio_unique_identifier: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			opclass: {
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
						channel_list: {
							type: "string",
							required: true
						},
						preference: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 16
						},
						reason_code: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 16
						}
					}
				}
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

		const opclass_count = ord(payload, offset++);

		const opclass = [];
		for (let i = 0; i < opclass_count; i++) {
			if (offset + 3 >= len)
				return null;

			const opclass = ord(payload, offset++);
			const channels_count = ord(payload, offset++);

			if (offset + channels_count >= len)
				return null;

			const channel_list = substr(payload, offset, channels_count);
			offset += channels_count;

			const bitfield = ord(payload, offset++);
			const preference = (bitfield >> 4) & 0b1111;
			const reason_code = bitfield & 0b1111;

			push(opclass, {
				opclass,
				channels_count,
				channel_list,
				preference,
				reason_code,
			});
		}

		if (offset < len)
			return null;

		return {
			radio_unique_identifier,
			opclass,
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

		if (type(tlv.opclass) != "array" || length(tlv.opclass) > 0xff)
			return null;

		push(fmt, "6s");
		push(val, radio_unique_identifier);

		push(fmt, "B");
		push(val, length(tlv.opclass));

		for (let item in tlv.opclass) {
			if (type(item) != "object")
				return null;

			if (type(item.opclass) != "int" || item.opclass < 0 || item.opclass > 0xff)
				return null;

			if (type(item.channel_list) != "string" || length(item.channel_list) > 0xff)
				return null;

			if (type(item.preference) != "int" || item.preference < 0 || item.preference > 0b1111)
				return null;

			if (type(item.reason_code) != "int" || item.reason_code < 0 || item.reason_code > 0b1111)
				return null;

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "B");
			push(val, length(item.channel_list));

			push(fmt, "*");
			push(val, item.channel_list);

			push(fmt, "B");
			push(val, 0
				| ((item.preference & 0b1111) << 4)
				| ((item.reason_code & 0b1111) << 0)
			);

		}

		return pack(join("", fmt), ...val);
	},

};
