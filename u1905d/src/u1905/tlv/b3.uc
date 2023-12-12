import defs from 'u1905.defs';

export default {
	type: 0xb3,
	name: 'Multi-AP Profile',

	/** @param string payload */
	decode: (payload) => {
		if (length(payload) != 1)
			return null;

		let profile = ord(payload, 0);
		let profile_name = defs.MULTI_AP_PROFILES[profile];

		return profile_name ? { profile, profile_name } : null;
	},

	/* Encoding not supported */
	encode: null,
};
