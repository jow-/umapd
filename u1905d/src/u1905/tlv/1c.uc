import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x1c,
	name: 'Interface power change information',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1 || ((len - 1) % 7))
			return null;

		let num_ifaces = ord(payload, 0);

		if (1 + num_ifaces * 7 != len)
			return null;

		let res = [];

		for (let off = 1; off < len; off += 7) {
			let power_state = ord(payload, off + 6);
			let power_state_name = defs.POWER_STATES[power_state];

			if (!power_state_name)
				return null;

			push(res, {
				local_address: utils.ether_ntoa(payload, off),
				power_state, power_state_name
			});
		}

		return res;
	},

	/* Encoding not supported */
	encode: null,
};
