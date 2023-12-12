import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x06,
	name: 'Non-1905 neighbor device list',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len <= 6 || (len % 6))
			return null;

		let res = [];

		for (let off = 0; off < len; off += 6)
			push(res, utils.ether_ntoa(payload, off));

		return res;
	},

	/** @param string local_address
	 *  @param string[] remote_addresses */
	encode: (local_address, remote_addresses) => {
		let fmt = '!6s',
			val = [ hexdec(local_address, ':') ];

		for (let addr in remote_addresses) {
			fmt += '6s';
			push(val, hexdec(addr, ':'));
		}

		return pack(fmt, ...val);
	},
};
