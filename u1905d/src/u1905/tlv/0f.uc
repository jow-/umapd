import { pack } from 'struct';
import defs from 'u1905.defs';

export default {
	type: 0x0f,
	name: 'SupportedRole',

	/** @param string payload */
	decode: (payload) => {
		if (length(payload) != 1)
			return null;

		let role = ord(payload, 0);
		let role_name = defs.SEARCHED_ROLES[role];

		return role_name ? { role, role_name } : null;
	},

	/** @param number role */
	encode: (role) => pack('!B', role),
};
