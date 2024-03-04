import { pack, unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x98,
	name: 'Unassociated STA Link Metrics Response',

	schema: {
		type: "object",
		properties: {
			opclass: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			sta_entries: {
				type: "array",
				required: true,
				items: {
					type: "object",
					properties: {
						mac_address_of_sta: {
							type: "string",
							required: true,
							pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
						},
						channel_number: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						time_delta: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 4294967295
						},
						uplink_rcpi_for_sta: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 220
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
		const sta_entries_count = ord(payload, offset++);

		const sta_entries = [];
		for (let i = 0; i < sta_entries_count; i++) {
			if (offset + 12 >= len)
				return null;

			const mac_address_of_sta = utils.ether_ntoa(payload, offset);
			offset += 6;

			const channel_number = ord(payload, offset++);

			const time_delta = unpack('!L', payload, offset);
			offset += 4;

			const uplink_rcpi_for_sta = ord(payload, offset++);

			if (uplink_rcpi_for_sta > 0xdc)
				return null;

			push(sta_entries, {
				mac_address_of_sta,
				channel_number,
				time_delta,
				uplink_rcpi_for_sta,
			});
		}

		if (offset < len)
			return null;

		return {
			opclass,
			sta_entries,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.opclass) != "int" || tlv.opclass < 0 || tlv.opclass > 0xff)
			return null;

		if (type(tlv.sta_entries) != "array" || length(tlv.sta_entries) > 0xff)
			return null;

		push(fmt, "B");
		push(val, tlv.opclass);

		push(fmt, "B");
		push(val, length(tlv.sta_entries));

		for (let item in tlv.sta_entries) {
			if (type(item) != "object")
				return null;

			const mac_address_of_sta = utils.ether_aton(item.mac_address_of_sta);
			if (mac_address_of_sta == null)
				return null;

			if (type(item.channel_number) != "int" || item.channel_number < 0 || item.channel_number > 0xff)
				return null;

			if (type(item.time_delta) != "int" || item.time_delta < 0 || item.time_delta > 0xffffffff)
				return null;

			if (type(item.uplink_rcpi_for_sta) != "int" || item.uplink_rcpi_for_sta < 0 || item.uplink_rcpi_for_sta > 220)
				return null;

			push(fmt, "6s");
			push(val, mac_address_of_sta);

			push(fmt, "B");
			push(val, item.channel_number);

			push(fmt, "!L");
			push(val, item.time_delta);

			push(fmt, "B");
			push(val, item.uplink_rcpi_for_sta);

		}

		return pack(join("", fmt), ...val);
	},

};
