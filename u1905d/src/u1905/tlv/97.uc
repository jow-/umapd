import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x97,
	name: 'Unassociated STA Link Metrics Query',

	schema: {
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
						sta_mac_addresses: {
							type: "array",
							required: true,
							items: {
								type: "string",
								required: true,
								pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
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
		const opclass = ord(payload, offset++);
		const channels_count = ord(payload, offset++);

		const channels = [];
		for (let i = 0; i < channels_count; i++) {
			if (offset + 2 >= len)
				return null;

			const channel_number = ord(payload, offset++);
			const sta_mac_addresses_count = ord(payload, offset++);

			const sta_mac_addresses = [];
			for (let j = 0; j < sta_mac_addresses_count; j++) {
				if (offset + 6 >= len)
					return null;

				const sta_mac_address = utils.ether_ntoa(payload, offset);
				offset += 6;

				push(sta_mac_addresses, sta_mac_address);
			}

			push(channels, {
				channel_number,
				sta_mac_addresses,
			});
		}

		if (offset < len)
			return null;

		return {
			opclass,
			channels,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.opclass) != "int" || tlv.opclass < 0 || tlv.opclass > 0xff)
			return null;

		if (type(tlv.channels) != "array" || length(tlv.channels) > 0xff)
			return null;

		push(fmt, "B");
		push(val, tlv.opclass);

		push(fmt, "B");
		push(val, length(tlv.channels));

		for (let item in tlv.channels) {
			if (type(item) != "object")
				return null;

			if (type(item.channel_number) != "int" || item.channel_number < 0 || item.channel_number > 0xff)
				return null;

			if (type(item.sta_mac_addresses) != "array" || length(item.sta_mac_addresses) > 0xff)
				return null;

			push(fmt, "B");
			push(val, item.channel_number);

			push(fmt, "B");
			push(val, length(item.sta_mac_addresses));

			for (let sta_mac_address in item.sta_mac_addresses) {
				const _sta_mac_address = utils.ether_aton(sta_mac_address);
				if (_sta_mac_address == null)
					return null;

				push(fmt, "6s");
				push(val, _sta_mac_address);

			}

		}

		return pack(join("", fmt), ...val);
	},

};
