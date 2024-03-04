import { pack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x89,
	name: 'Steering Policy',

	schema: {
		type: "object",
		properties: {
			local_steering_disallowed_sta: {
				type: "array",
				required: true,
				items: {
					type: "string",
					required: true,
					pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
				}
			},
			btm_steering_disallowed_sta: {
				type: "array",
				required: true,
				items: {
					type: "string",
					required: true,
					pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
				}
			},
			radios: {
				type: "array",
				required: true,
				items: {
					type: "object",
					properties: {
						radio_unique_identifier_of_an_ap_radio: {
							type: "string",
							required: true,
							pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
						},
						steering_policy: {
							type: "integer",
							required: true,
							enum: [ 0x00, 0x01, 0x02 ]
						},
						channel_utilization_threshold: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						rcpi_steering_threshold: {
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

		if (len < 3)
			return null;

		let offset = 0;
		const local_steering_disallowed_sta_count = ord(payload, offset++);

		const local_steering_disallowed_sta = [];
		for (let i = 0; i < local_steering_disallowed_sta_count; i++) {
			if (offset + 6 >= len)
				return null;

			const sta_mac_address = utils.ether_ntoa(payload, offset);
			offset += 6;

			push(local_steering_disallowed_sta, sta_mac_address);
		}

		const btm_steering_disallowed_sta_count = ord(payload, offset++);

		const btm_steering_disallowed_sta = [];
		for (let i = 0; i < btm_steering_disallowed_sta_count; i++) {
			if (offset + 6 >= len)
				return null;

			const sta_mac_address = utils.ether_ntoa(payload, offset);
			offset += 6;

			push(btm_steering_disallowed_sta, sta_mac_address);
		}

		const radios_count = ord(payload, offset++);

		const radios = [];
		for (let i = 0; i < radios_count; i++) {
			if (offset + 9 >= len)
				return null;

			const radio_unique_identifier_of_an_ap_radio = utils.ether_ntoa(payload, offset);
			offset += 6;

			const steering_policy = ord(payload, offset++);

			if (!exists(defs.STEERING_POLICY, steering_policy))
				return null;

			const channel_utilization_threshold = ord(payload, offset++);
			const rcpi_steering_threshold = ord(payload, offset++);

			if (rcpi_steering_threshold > 0xdc)
				return null;

			push(radios, {
				radio_unique_identifier_of_an_ap_radio,
				steering_policy,
				steering_policy_name: defs.STEERING_POLICY[steering_policy],
				channel_utilization_threshold,
				rcpi_steering_threshold,
			});
		}

		if (offset < len)
			return null;

		return {
			local_steering_disallowed_sta,
			btm_steering_disallowed_sta,
			radios,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.local_steering_disallowed_sta) != "array" || length(tlv.local_steering_disallowed_sta) > 0xff)
			return null;

		if (type(tlv.btm_steering_disallowed_sta) != "array" || length(tlv.btm_steering_disallowed_sta) > 0xff)
			return null;

		if (type(tlv.radios) != "array" || length(tlv.radios) > 0xff)
			return null;

		push(fmt, "B");
		push(val, length(tlv.local_steering_disallowed_sta));

		for (let sta_mac_address in tlv.local_steering_disallowed_sta) {
			const _sta_mac_address = utils.ether_aton(sta_mac_address);
			if (_sta_mac_address == null)
				return null;

			push(fmt, "6s");
			push(val, _sta_mac_address);

		}

		push(fmt, "B");
		push(val, length(tlv.btm_steering_disallowed_sta));

		for (let sta_mac_address in tlv.btm_steering_disallowed_sta) {
			const _sta_mac_address = utils.ether_aton(sta_mac_address);
			if (_sta_mac_address == null)
				return null;

			push(fmt, "6s");
			push(val, _sta_mac_address);

		}

		push(fmt, "B");
		push(val, length(tlv.radios));

		for (let item in tlv.radios) {
			if (type(item) != "object")
				return null;

			const radio_unique_identifier_of_an_ap_radio = utils.ether_aton(item.radio_unique_identifier_of_an_ap_radio);
			if (radio_unique_identifier_of_an_ap_radio == null)
				return null;

			if (!(item.steering_policy in [ 0x00, 0x01, 0x02 ]))
				return null;

			if (type(item.channel_utilization_threshold) != "int" || item.channel_utilization_threshold < 0 || item.channel_utilization_threshold > 0xff)
				return null;

			if (type(item.rcpi_steering_threshold) != "int" || item.rcpi_steering_threshold < 0 || item.rcpi_steering_threshold > 220)
				return null;

			push(fmt, "6s");
			push(val, radio_unique_identifier_of_an_ap_radio);

			push(fmt, "B");
			push(val, item.steering_policy);

			push(fmt, "B");
			push(val, item.channel_utilization_threshold);

			push(fmt, "B");
			push(val, item.rcpi_steering_threshold);

		}

		return pack(join("", fmt), ...val);
	},

};
