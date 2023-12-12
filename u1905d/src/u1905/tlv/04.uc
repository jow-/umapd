import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x04,
	name: 'Device bridging capability',

	/** @param string payload */
	decode: (payload) => {
		let off = 0,
			res = null,
			n_tuples = ord(payload, off++);

		while (n_tuples > 0) {
			n_tuples--;

			let n_macs = ord(payload, off++);

			if (n_macs > 0) {
				let tuple = [];

				while (n_macs > 0) {
					push(tuple, utils.ether_ntoa(payload, off));
					n_macs--;
					off += 6;
				}

				push(res ??= [], tuple);
			}
		}

		return res;
	},

	/** @param Array<string[]> tuples */
	encode: (tuples) => {
		if (length(tuples) == 0 || length(tuples) > 255)
			return null;

		let fmt = '!B',
			val = [ length(tuples) ];

		for (let tuple in tuples) {
			if (length(tuple) == 0)
				continue;

			if (length(tuple) > 255)
				return null;

			fmt += 'B';
			push(val, length(tuple));

			for (let mac in tuple) {
				fmt += '6s';
				push(val, hexdec(mac, ':'));
			}
		}

		return pack(fmt, ...val);
	},
};
