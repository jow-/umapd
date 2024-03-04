import { pack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0xaf,
	name: 'CAC Completion Report',

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
				},
				cac_completion_status: {
					type: "integer",
					required: true,
					enum: [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 ]
				},
				pairs: {
					type: "array",
					required: true,
					items: {
						type: "object",
						properties: {
							opclass_detected: {
								type: "integer",
								required: true,
								minimum: 0,
								maximum: 255
							},
							channel_detected: {
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
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const radios_count = ord(payload, offset++);

		const radios = [];
		for (let i = 0; i < radios_count; i++) {
			if (offset + 10 >= len)
				return null;

			const radio_unique_identifier = utils.ether_ntoa(payload, offset);
			offset += 6;

			const opclass = ord(payload, offset++);
			const channel = ord(payload, offset++);
			const cac_completion_status = ord(payload, offset++);

			if (!exists(defs.CAC_COMPLETION_STATUS, cac_completion_status))
				return null;

			const pairs_count = ord(payload, offset++);

			const pairs = [];
			for (let j = 0; j < pairs_count; j++) {
				if (offset + 2 >= len)
					return null;

				const opclass_detected = ord(payload, offset++);
				const channel_detected = ord(payload, offset++);

				push(pairs, {
					opclass_detected,
					channel_detected,
				});
			}

			push(radios, {
				radio_unique_identifier,
				opclass,
				channel,
				cac_completion_status,
				cac_completion_status_name: defs.CAC_COMPLETION_STATUS[cac_completion_status],
				pairs,
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

			if (!(item.cac_completion_status in [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 ]))
				return null;

			if (type(item.pairs) != "array" || length(item.pairs) > 0xff)
				return null;

			push(fmt, "6s");
			push(val, radio_unique_identifier);

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "B");
			push(val, item.channel);

			push(fmt, "B");
			push(val, item.cac_completion_status);

			push(fmt, "B");
			push(val, length(item.pairs));

			for (let item2 in item.pairs) {
				if (type(item2) != "object")
					return null;

				if (type(item2.opclass_detected) != "int" || item2.opclass_detected < 0 || item2.opclass_detected > 0xff)
					return null;

				if (type(item2.channel_detected) != "int" || item2.channel_detected < 0 || item2.channel_detected > 0xff)
					return null;

				push(fmt, "B");
				push(val, item2.opclass_detected);

				push(fmt, "B");
				push(val, item2.channel_detected);

			}

		}

		return pack(join("", fmt), ...val);
	},

};
