import { pack, unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xa5,
	name: 'Channel Scan Capabilities',

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
				on_boot_only: {
					type: "boolean"
				},
				scan_impact: {
					type: "integer",
					required: true,
					enum: [ 0x00, 0x01, 0x02, 0x03 ]
				},
				minimum_scan_interval: {
					type: "integer",
					required: true,
					minimum: 0,
					maximum: 4294967295
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
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const radios_count = ord(payload, offset++);

		const radios = [];
		for (let i = 0; i < radios_count; i++) {
			if (offset + 12 >= len)
				return null;

			const radio_unique_identifier = utils.ether_ntoa(payload, offset);
			offset += 6;

			const bitfield = ord(payload, offset++);
			const on_boot_only = ((bitfield & 0b10000000) == 0b10000000);
			const scan_impact = (bitfield >> 5) & 0b11;

			const minimum_scan_interval = unpack('!L', payload, offset);
			offset += 4;

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
				on_boot_only,
				scan_impact,
				scan_impact_name: defs.SCAN_IMPACT[scan_impact],
				minimum_scan_interval,
				opclass,
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

			if (type(item.on_boot_only) != "bool")
				return null;

			if (!(item.scan_impact in [ 0x00, 0x01, 0x02, 0x03 ]))
				return null;

			if (type(item.minimum_scan_interval) != "int" || item.minimum_scan_interval < 0 || item.minimum_scan_interval > 0xffffffff)
				return null;

			if (type(item.opclass) != "array" || length(item.opclass) > 0xff)
				return null;

			push(fmt, "6s");
			push(val, radio_unique_identifier);

			push(fmt, "B");
			push(val, 0
				| (item.on_boot_only << 7)
				| ((item.scan_impact & 0b11) << 5)
			);

			push(fmt, "L");
			push(val, item.minimum_scan_interval);

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
