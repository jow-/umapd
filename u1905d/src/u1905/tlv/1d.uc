import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x1d,
	name: 'Interface power change status',

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
			let change_status = ord(payload, off + 6);
			let change_status_name = defs.POWER_CHANGE_RESULT_CODES[change_status];

			if (!change_status_name)
				return null;

			push(res, {
				local_address: utils.ether_ntoa(payload, off),
				change_status, change_status_name
			});
		}

		return res;
	},

	/* Encoding not supported */
	encode: null,
};
