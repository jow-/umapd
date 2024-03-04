import { pack, unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0xb2,
	name: 'CAC Capabilities',

	schema: {
		type: "object",
		properties: {
			country_code: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 65535
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
						cac_types_supported: {
							type: "array",
							required: true,
							items: {
								type: "object",
								properties: {
									cac_method_supported: {
										type: "integer",
										required: true,
										enum: [ 0x00, 0x01, 0x02, 0x03 ]
									},
									duration: {
										type: "string",
										required: true,
										minLength: 3,
										maxLength: 3
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
					}
				}
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 3)
			return null;

		let offset = 0;

		const country_code = unpack('!H', payload, offset);
		offset += 2;

		const radios_count = ord(payload, offset++);

		const radios = [];
		for (let i = 0; i < radios_count; i++) {
			if (offset + 7 >= len)
				return null;

			const radio_unique_identifier = utils.ether_ntoa(payload, offset);
			offset += 6;

			const cac_types_supported_count = ord(payload, offset++);

			const cac_types_supported = [];
			for (let j = 0; j < cac_types_supported_count; j++) {
				if (offset + 5 >= len)
					return null;

				const cac_method_supported = ord(payload, offset++);

				if (!exists(defs.CAC_METHOD_SUPPORTED, cac_method_supported))
					return null;

				const duration = unpack('3s', payload, offset);
				offset += 3;

				const opclass_count = ord(payload, offset++);

				const opclass = [];
				for (let k = 0; k < opclass_count; k++) {
					if (offset + 2 >= len)
						return null;

					const opclass = ord(payload, offset++);
					const channels_count = ord(payload, offset++);

					const channels = [];
					for (let l = 0; l < channels_count; l++) {
						if (offset + 1 >= len)
							return null;

						const channel = ord(payload, offset++);

						push(channels, channel);
					}

					push(opclass, {
						opclass,
						channels,
					});
				}

				push(cac_types_supported, {
					cac_method_supported,
					cac_method_supported_name: defs.CAC_METHOD_SUPPORTED[cac_method_supported],
					duration,
					opclass,
				});
			}

			push(radios, {
				radio_unique_identifier,
				cac_types_supported,
			});
		}

		if (offset < len)
			return null;

		return {
			country_code,
			radios,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.country_code) != "int" || tlv.country_code < 0 || tlv.country_code > 0xffff)
			return null;

		if (type(tlv.radios) != "array" || length(tlv.radios) > 0xff)
			return null;

		push(fmt, "H");
		push(val, tlv.country_code);

		push(fmt, "B");
		push(val, length(tlv.radios));

		for (let item in tlv.radios) {
			if (type(item) != "object")
				return null;

			const radio_unique_identifier = utils.ether_aton(item.radio_unique_identifier);
			if (radio_unique_identifier == null)
				return null;

			if (type(item.cac_types_supported) != "array" || length(item.cac_types_supported) > 0xff)
				return null;

			push(fmt, "6s");
			push(val, radio_unique_identifier);

			push(fmt, "B");
			push(val, length(item.cac_types_supported));

			for (let item2 in item.cac_types_supported) {
				if (type(item2) != "object")
					return null;

				if (!(item2.cac_method_supported in [ 0x00, 0x01, 0x02, 0x03 ]))
					return null;

				if (type(item2.duration) != "string" || length(item2.duration) > 3)
					return null;

				if (type(item2.opclass) != "array" || length(item2.opclass) > 0xff)
					return null;

				push(fmt, "B");
				push(val, item2.cac_method_supported);

				push(fmt, "3s");
				push(val, item2.duration);

				push(fmt, "B");
				push(val, length(item2.opclass));

				for (let item3 in item2.opclass) {
					if (type(item3) != "object")
						return null;

					if (type(item3.opclass) != "int" || item3.opclass < 0 || item3.opclass > 0xff)
						return null;

					if (type(item3.channels) != "array" || length(item3.channels) > 0xff)
						return null;

					push(fmt, "B");
					push(val, item3.opclass);

					push(fmt, "B");
					push(val, length(item3.channels));

					for (let channel in item3.channels) {
						if (type(channel) != "int" || channel < 0 || channel > 0xff)
							return null;

						push(fmt, "B");
						push(val, channel);

					}

				}

			}

		}

		return pack(join("", fmt), ...val);
	},

};
