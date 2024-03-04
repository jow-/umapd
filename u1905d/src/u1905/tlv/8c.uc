import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x8c,
	name: 'Radio Operation Restriction',

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
						channels: {
							type: "array",
							required: true,
							items: {
								type: "object",
								properties: {
									channel_number: {
										type: "integer",
										required: true,
										minimum: 0,
										maximum: 255
									},
									minimum_frequency_separation: {
										type: "integer",
										required: true,
										minimum: 0,
										maximum: 255
									}
								}
							}
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
			if (offset + 2 >= len)
				return null;

			const opclass = ord(payload, offset++);
			const channels_count = ord(payload, offset++);

			const channels = [];
			for (let j = 0; j < channels_count; j++) {
				if (offset + 2 >= len)
					return null;

				const channel_number = ord(payload, offset++);
				const minimum_frequency_separation = ord(payload, offset++);

				push(channels, {
					channel_number,
					minimum_frequency_separation,
				});
			}

			push(opclass, {
				opclass,
				channels,
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

			if (type(item.channels) != "array" || length(item.channels) > 0xff)
				return null;

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "B");
			push(val, length(item.channels));

			for (let item2 in item.channels) {
				if (type(item2) != "object")
					return null;

				if (type(item2.channel_number) != "int" || item2.channel_number < 0 || item2.channel_number > 0xff)
					return null;

				if (type(item2.minimum_frequency_separation) != "int" || item2.minimum_frequency_separation < 0 || item2.minimum_frequency_separation > 0xff)
					return null;

				push(fmt, "B");
				push(val, item2.channel_number);

				push(fmt, "B");
				push(val, item2.minimum_frequency_separation);

			}

		}

		return pack(join("", fmt), ...val);
	},

};
