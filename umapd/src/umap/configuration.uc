/*
 * Copyright (c) 2024 Jo-Philipp Wich <jo@mein.io>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

import { cursor } from 'uci';

import log from 'umap.log';
import * as wconst from 'umap.wireless';

const valid_authentications = ['open', 'psk', 'wpa', 'wpa2', 'psk2', 'sae'];
const valid_ciphers = ['none', 'tkip', 'ccmp', 'aes'];
const valid_bands = ['2g', '5g', '60g', '6g'];

function to_array(x) {
	switch (type(x)) {
		case 'array': return length(x) ? x : null;
		case 'string': return [x];
	}
}

export default {
	bssConfigurationProfiles: [],

	reload: function () {
		while (length(this.bssConfigurationProfiles))
			pop(this.bssConfigurationProfiles);

		this.parseBSSConfigurations();
	},

	addBSSConfiguration: function (settings) {
		push(this.bssConfigurationProfiles, settings);
	},

	parseBSSConfigurations: function () {
		const bssConfigs = this.bssConfigurationProfiles;

		cursor().foreach('umapd', null, section => {
			if (section['.type'] != 'backhaul' && section['.type'] != 'fronthaul')
				return;

			const authentication = map(to_array(section.authentication), x => lc(x));
			const ciphers = map(to_array(section.ciphers), x => lc(x));
			const bands = map(to_array(section.band), x => lc(x));

			if (length(filter(authentication, a => !(a in valid_authentications))))
				return log.warn(`Invalid authentication method(s) in umapd.${section['.name']}`);

			if (length(filter(ciphers, a => !(a in valid_ciphers))))
				return log.warn(`Invalid ciphers(s) in umapd.${section['.name']}`);

			if (length(filter(bands, a => !(a in valid_bands))))
				return log.warn(`Invalid bands(s) in umapd.${section['.name']}`);

			if (length(section.ssid) == 0 || length(section.ssid) > 32)
				return log.warn(`Invalid ssid in umapd.${section['.name']}`);

			if (length(section.key) != 0 && length(section.key) < 8 && length(section.key) > 63)
				return log.warn(`Invalid key length in umapd.${section['.name']}`);

			const default_ciphers = [];

			const bss = {
				type: section['.type'],
				ssid: section.ssid,
				key: section.key,
				hidden: (section.hidden in ['1', 'on', 'yes', 'true']),
				auth_mask: 0,
				cipher_mask: 0,
				band_mask: 0
			};

			for (let a in authentication ?? ['open']) {
				switch (a) {
					case 'open':
						bss.auth_mask |= wconst.WPS_AUTH_OPEN;
						push(default_ciphers, 'none');
						break;

					case 'psk':
						bss.auth_mask |= wconst.WPS_AUTH_WPAPSK;
						push(default_ciphers, 'tkip');
						break;

					case 'wpa':
						bss.auth_mask |= wconst.WPS_AUTH_WPA;
						push(default_ciphers, 'tkip');
						break;

					case 'wpa2':
						bss.auth_mask |= wconst.WPS_AUTH_WPA2;
						push(default_ciphers, 'aes');
						break;

					case 'psk2':
						bss.auth_mask |= wconst.WPS_AUTH_WPA2PSK;
						push(default_ciphers, 'aes');
						break;

					case 'sae':
						bss.auth_mask |= wconst.WPS_AUTH_SAE;
						push(default_ciphers, 'aes');
						break;
				}
			}

			for (let c in ciphers ?? default_ciphers) {
				switch (c) {
					case 'none': bss.cipher_mask |= wconst.WPS_ENCR_NONE; break;
					case 'tkip': bss.cipher_mask |= wconst.WPS_ENCR_TKIP; break;
					case 'ccmp': bss.cipher_mask |= wconst.WPS_ENCR_AES; break;
					case 'aes': bss.cipher_mask |= wconst.WPS_ENCR_AES; break;
				}
			}

			for (let b in bands ?? ['2g', '5g']) {
				switch (b) {
					case '2g': bss.band_mask |= wconst.WPS_RF_2GHZ; break;
					case '5g': bss.band_mask |= wconst.WPS_RF_5GHZ; break;
					case '60g': bss.band_mask |= wconst.WPS_RF_60GHZ; break;
					case '6g': bss.band_mask |= wconst.WPS_RF_6GHZ; break;
				}
			}

			push(bssConfigs, bss);
		});
	},

	selectBSSConfigurations: function (band_mask, auth_mask, cipher_mask) {
		return sort(
			filter(this.bssConfigurationProfiles, net =>
				(!band_mask || (net.band_mask & band_mask)) &&
				(!auth_mask || (net.auth_mask & auth_mask)) &&
				(!cipher_mask || (net.cipher_mask & cipher_mask))
			),
			(a, b) => {
				// Prefer matching all requested bands
				if (band_mask) {
					let a_matches = (a.band_mask & band_mask) == band_mask;
					let b_matches = (b.band_mask & band_mask) == band_mask;
					if (a_matches != b_matches)
						return a_matches ? -1 : 1;
				}

				// Compare auth strength (prefer stronger auth)
				let a_auth = a.auth_mask & auth_mask;
				let b_auth = b.auth_mask & auth_mask;
				if (a_auth != b_auth)
					return b_auth - a_auth;

				// Prefer AES over TKIP
				if ((a.cipher_mask & wconst.WPS_ENCR_AES) != (b.cipher_mask & wconst.WPS_ENCR_AES))
					return (b.cipher_mask & wconst.WPS_ENCR_AES) ? 1 : -1;

				return 0;
			}
		);
	}
};
