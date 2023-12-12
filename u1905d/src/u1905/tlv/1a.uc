import { pack } from 'struct';
import defs from 'u1905.defs';

export default {
	type: 0x1a,
	name: '1905 profile version',

	/** @param string payload */
	decode: (payload) => {
		if (length(payload) != 1)
			return null;

		let version = ord(payload, 0);
		let version_name = defs.IEEE1905_PROFILE_VERSIONS[version];

		return version_name ? { version, version_name } : null;
	},

	/** @param numbe version */
	encode: (version) => pack('!B', version),
};
