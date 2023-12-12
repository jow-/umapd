import { unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

function decode_media_info(media_type, media_info) {
	if ((media_type & 0xff00) == 0x0100) {
		let mi = unpack('!6sBBBB', media_info);

		if (!mi)
			return null;

		return {
			bssid: utils.ether_ntoa(mi[0]),
			role: mi[1],
			role_name: defs.IEEE80211_ROLES[mi[1]] ?? 'Unknown/Reserved',
			bandwidth: mi[2],
			channel1: mi[3],
			channel2: mi[4]
		};
	}

	return null;
}

export default {
	type: 0x12,
	name: 'Push_Button_Event notification',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_types = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; i < num_types && off < len; i++) {
			if (off + 3 > len)
				return null;

			let values = unpack('!HB', payload, off);

			if (off + 3 + values[1] > len)
				return null;

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res, {
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]]
			});

			if (values[1])
				res[-1].media_info =
					decode_media_info(values[0], substr(payload, off + 3, values[1]));

			off += 3 + values[1];
		}

		return res;
	},

	/* Encoding unsupported */
	encode: null,
};
