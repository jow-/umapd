import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x08,
	name: 'Link metric query',

	/** @param string payload */
	decode: (payload) => {
		if (length(payload) < 2)
			return null;

		let neigh = ord(payload, 0),
			mac = null,
			off = 1;

		switch (neigh) {
		case 0x00:
			break;

		case 0x01:
			mac = utils.ether_ntoa(payload, off);
			off += 6;
			break;

		default:
			return null;
		}

		switch (ord(payload, off)) {
		case 0x00:
			return { mac, tx: true, rx: false };

		case 0x01:
			return { mac, tx: false, rx: true };

		case 0x02:
			return { mac, tx: true, rx: true };

		default:
			return null;
		}
	},

	/** @param ?string address
	 *  @param boolean rx
	 *  @param boolean tx */
	encode: (address, rx, tx) => {
		let metrics;

		if (rx && tx)
			metrics = 0x02;
		else if (rx)
			metrics = 0x01;
		else /* if (tx) */
			metrics = 0x00;

		return pack('!B*B',
			address ? 0x01 : 0x00,
			address ? hexdec(address, ':') : '',
			metrics
		);
	},
};
