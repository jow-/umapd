import { unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x94,
	name: 'AP Metrics',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 10)
			return null;

		let res = {
			bssid: utils.ether_ntoa(payload, 0),
			channel_utilization: ord(payload, 6),
			num_associated: unpack('!H', payload, 7)[0],
			esp_information: []
		};

		let off = 9;
		let have_espinfo = ord(payload, off++);

		for (let i = 0; i < 4 && off < len; i++) {
			if (off + 3 > len)
				return null;

			let values = unpack('!BBB', payload, off);

			off += 3;

			push(res.esp_information, {
				access_category: values[2] & 0x03,
				data_format: (values[2] & 0x18) >> 3,
				ba_window_size: (values[2] & 0xe0) >> 5,
				data_ppdu_duration_target: values[0],
				estimated_air_time_fraction: values[1]
			});
		}

		return res;
	},

	/* Encoding not supported */
	encode: null,
};
