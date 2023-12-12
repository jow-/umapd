import { pack } from 'struct';
import defs from 'u1905.defs';

export default {
	type: 0x0e,
	name: 'AutoconfigFreqBand',

	/** @param string payload */
	decode: (payload) => {
		if (length(payload) != 1)
			return null;

		let band = ord(payload, 0);
		let band_name = defs.IEEE80211_BANDS[band];

		return band_name ? { band, band_name } : null;
	},

	/** @param number band */
	encode: (band) => pack('!B', band),
};
