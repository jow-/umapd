import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xa6,
	name: 'Channel Scan Request',

	schema: {
		type: "object",
		properties: {
			perform_fresh_scan: {
				type: "boolean"
			},
			radios: {
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

		if (len < 2)
			return null;

		let offset = 0;
		const bitfield = ord(payload, offset++);
		const perform_fresh_scan = ((bitfield & 0b10000000) == 0b10000000);

		const radios_count = ord(payload, offset++);

		const radios = [];
		for (let i = 0; i < radios_count; i++) {
			if (offset + 7 >= len)
				return null;

			const radio_unique_identifier = utils.ether_ntoa(payload, offset);
			offset += 6;

			const opclass_count = ord(payload, offset++);

			const opclass = [];
			for (let j = 0; j < opclass_count; j++) {
				if (offset + 2 >= len)
					return null;

				const opclass = ord(payload, offset++);
				const channels_count = ord(payload, offset++);

				if (offset + channels_count >= len)
					return null;

				const channel_list = substr(payload, offset, channels_count);
				offset += channels_count;

				push(opclass, {
					opclass,
					channels_count,
					channel_list,
				});
			}

			push(radios, {
				radio_unique_identifier,
				opclass,
			});
		}

		if (offset < len)
			return null;

		return {
			perform_fresh_scan,
			radios,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.perform_fresh_scan) != "bool")
			return null;

		if (type(tlv.radios) != "array" || length(tlv.radios) > 0xff)
			return null;

		push(fmt, "B");
		push(val, 0
			| (tlv.perform_fresh_scan << 7)
		);

		push(fmt, "B");
		push(val, length(tlv.radios));

		for (let item in tlv.radios) {
			if (type(item) != "object")
				return null;

			const radio_unique_identifier = utils.ether_aton(item.radio_unique_identifier);
			if (radio_unique_identifier == null)
				return null;

			if (type(item.opclass) != "array" || length(item.opclass) > 0xff)
				return null;

			push(fmt, "6s");
			push(val, radio_unique_identifier);

			push(fmt, "B");
			push(val, length(item.opclass));

			for (let item2 in item.opclass) {
				if (type(item2) != "object")
					return null;

				if (type(item2.opclass) != "int" || item2.opclass < 0 || item2.opclass > 0xff)
					return null;

				if (type(item2.channel_list) != "string" || length(item2.channel_list) > 0xff)
					return null;

				push(fmt, "B");
				push(val, item2.opclass);

				push(fmt, "B");
				push(val, length(item2.channel_list));

				push(fmt, "*");
				push(val, item2.channel_list);

			}

		}

		return pack(join("", fmt), ...val);
	},

};
