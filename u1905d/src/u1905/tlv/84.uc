import { unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x84,
	name: 'Associated Clients',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_bsses = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; i < num_bsses && off < len; i++) {
			if (off + 8 > len)
				return null;

			let bssid = utils.ether_ntoa(payload, off);
			let num_associated = unpack('!H', payload, off + 6)[0];

			off += 8;

			push(res, {
				bssid,
				clients: []
			});

			for (let j = 0; j < num_associated; j++) {
				if (off + 8 > len)
					return null;

				let mac = utils.ether_ntoa(payload, off);
				let last_seen = unpack('!H', payload, off + 6)[0];

				off += 8;

				push(res[-1].clients, {
					mac,
					last_seen
				});
			}
		}

		return res;
	},

	/* Encoding not supported */
	encode: null,
};
