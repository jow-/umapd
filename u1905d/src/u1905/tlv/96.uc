import { pack, unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x96,
	name: 'Associated STA Link Metrics',

	schema: {
		type: "object",
		properties: {
			mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			bssids: {
				type: "array",
				required: true,
				items: {
					type: "object",
					properties: {
						bssid: {
							type: "string",
							required: true,
							pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
						},
						time_delta: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 4294967295
						},
						estimated_mac_data_rate: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 4294967295
						},
						estimated_mac_data_rate2: {
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

		if (len < 7)
			return null;

		let offset = 0;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bssids_count = ord(payload, offset++);

		const bssids = [];
		for (let i = 0; i < bssids_count; i++) {
			if (offset + 19 >= len)
				return null;

			const bssid = utils.ether_ntoa(payload, offset);
			offset += 6;

			const time_delta = unpack('!L', payload, offset);
			offset += 4;

			const estimated_mac_data_rate = unpack('!L', payload, offset);
			offset += 4;

			const estimated_mac_data_rate2 = unpack('!L', payload, offset);
			offset += 4;

			const uplink_rcpi_for_sta = ord(payload, offset++);

			if (uplink_rcpi_for_sta > 0xdc)
				return null;

			push(bssids, {
				bssid,
				time_delta,
				estimated_mac_data_rate,
				estimated_mac_data_rate2,
				uplink_rcpi_for_sta,
			});
		}

		if (offset < len)
			return null;

		return {
			mac_address,
			bssids,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		const mac_address = utils.ether_aton(tlv.mac_address);
		if (mac_address == null)
			return null;

		if (type(tlv.bssids) != "array" || length(tlv.bssids) > 0xff)
			return null;

		push(fmt, "6s");
		push(val, mac_address);

		push(fmt, "B");
		push(val, length(tlv.bssids));

		for (let item in tlv.bssids) {
			if (type(item) != "object")
				return null;

			const bssid = utils.ether_aton(item.bssid);
			if (bssid == null)
				return null;

			if (type(item.time_delta) != "int" || item.time_delta < 0 || item.time_delta > 0xffffffff)
				return null;

			if (type(item.estimated_mac_data_rate) != "int" || item.estimated_mac_data_rate < 0 || item.estimated_mac_data_rate > 0xffffffff)
				return null;

			if (type(item.estimated_mac_data_rate2) != "int" || item.estimated_mac_data_rate2 < 0 || item.estimated_mac_data_rate2 > 0xffffffff)
				return null;

			if (type(item.uplink_rcpi_for_sta) != "int" || item.uplink_rcpi_for_sta < 0 || item.uplink_rcpi_for_sta > 220)
				return null;

			push(fmt, "6s");
			push(val, bssid);

			push(fmt, "L");
			push(val, item.time_delta);

			push(fmt, "L");
			push(val, item.estimated_mac_data_rate);

			push(fmt, "L");
			push(val, item.estimated_mac_data_rate2);

			push(fmt, "B");
			push(val, item.uplink_rcpi_for_sta);

		}

		return pack(join("", fmt), ...val);
	},

};
