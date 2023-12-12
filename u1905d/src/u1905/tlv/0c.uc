import { pack } from 'struct';
import defs from 'u1905.defs';

export default {
	type: 0x0c,
	name: 'Link metric result code',

	/** @param string payload */
	decode: (payload) => {
		if (length(payload) != 1)
			return null;

		let code = ord(payload, 0);
		let code_name = defs.LINK_METRIC_RESULT_CODES[code];

		return code_name ? { code, code_name } : null;
	},

	/** @param number code */
	encode: (code) => pack('!B', code),
};
