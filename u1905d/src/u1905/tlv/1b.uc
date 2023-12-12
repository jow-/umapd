import { unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x1b,
	name: 'Power off interface',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_ifaces = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; off < len && i < num_ifaces; i++) {
			if (off + 13 > len)
				return null;

			let info_len = ord(payload, off + 13);

			if (off + 13 + info_len > len)
				return null;

			let values = unpack('!H3BB', payload, off + 6);

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res, {
				local_address: utils.ether_ntoa(payload, off),
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]],
				oui: sprintf('%02x:%02x:%02x', values[1], values[2], values[3]),
				variant_index: values[4]
			});

			if (info_len)
				res[-1].media_info = substr(payload, off + 13, info_len);

			off += 13 + info_len;
		}

		return res;
	},

	/* Encoding not supported */
	encode: null,
};
