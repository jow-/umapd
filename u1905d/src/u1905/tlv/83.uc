import utils from 'u1905.utils';

export default {
	type: 0x83,
	name: 'AP Operational BSS',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_radios = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; i < num_radios && off < len; i++) {
			if (off + 7 > len)
				return null;

			let radio_unique_id = utils.ether_ntoa(payload, off);
			let num_bsses = ord(payload, off + 6);

			off += 7;

			push(res, {
				radio_unique_id,
				bsses: []
			});

			for (let j = 0; j < num_bsses; j++) {
				if (off + 7 > len)
					return null;

				let bssid = utils.ether_ntoa(payload, off);
				let ssid_len = ord(payload, off + 6);

				off += 7;

				if (off + ssid_len > len)
					return null;

				let ssid = substr(payload, off, ssid_len);

				off += ssid_len;

				push(res[-1].bsses, {
					bssid,
					ssid
				});
			}
		}

		return res;
	},

	/* Encoding not supported */
	encode: null,
};
