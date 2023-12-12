import defs from 'u1905.defs';

export default {
	type: 0xb4,
	name: 'Profile-2 AP Capability',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 4)
			return null;

		let flags = ord(payload, 2);
		let unit = (flags >> 6) & 0b11;
		let unit_name = defs.PROFILE_2_BYTE_COUNTER_UNIT[unit];

		if (!unit_name)
			return null;

		return {
			max_priorization_rules: ord(payload, 0),
			max_unique_vids: ord(payload, 3),
			byte_counter_unit: unit,
			byte_counter_unit_name: unit_name,
			supports_traffic_separation: !!(flags & 0b00001000),
			supports_dpp_onboarding: !!(flags & 0b00010000),
			supports_priorization: !!(flags & 0b00100000),
		};
	},

	/* Encoding not supported */
	encode: null,
};
