import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x07,
	name: '1905.1 neighbor device',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len <= 6 || ((len - 6) % 7))
			return null;

		let res = {
			local_address: utils.ether_ntoa(payload),
			neighbors: []
		};

		for (let off = 6; off < len; off += 7) {
			push(res.neighbors, {
				neighbor_al_address: utils.ether_ntoa(payload, off),
				is_bridge: !!(ord(payload, off + 6) & 0b10000000)
			});
		}

		return res;
	},

	/** @param string local_address
	 *  @param i1905rif[] links */
	encode: (local_address, links) => {
		let fmt = '!6s',
			val = [ hexdec(local_address, ':') ];

		for (let i1905rif in links) {
			fmt += '6sB';
			push(val,
				hexdec(i1905rif.getDevice().al_address, ':'),
				i1905rif.isBridged() ? 0b10000000 : 0);
		}

		return pack(fmt, ...val);
	},
};
