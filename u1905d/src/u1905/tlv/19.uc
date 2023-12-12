import { pack, unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x19,
	name: 'Push_Button_Generic_Phy_Event notification',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_types = ord(payload, 0);

		if (num_types < 1)
			return null;

		let res = [];

		for (let i = 0, off = 1; off < len && i < num_types; i++) {
			if (off + 5 > len)
				return null;

			let info_len = ord(payload, off + 4);

			if (off + 5 + info_len > len)
				return null;

			push(res, {
				oui: sprintf('%02x:%02x:%02x', ...unpack('!3B', payload, off)),
				variant_index: ord(payload, off + 3)
			});

			if (info_len)
				res[-1].media_info = substr(payload, off + 5, info_len);

			off += 5 + info_len;
		}

		return res;
	},

	/* Encode not supported */
	encode: null,
};
