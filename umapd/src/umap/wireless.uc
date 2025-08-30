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

import { request as wlrequest, 'const' as wlconst, error as wlerror } from 'nl80211';
import { popen, readfile } from 'fs';
import { unpack, buffer } from 'struct';
import { cursor } from 'uci';
import { find_phy } from 'wifi.utils';

import events from 'umap.events';
import ubus from 'umap.ubusclient';
import log from 'umap.log';

/* shared constants */
export const WPS_AUTH_OPEN = 0x0001;
export const WPS_AUTH_WPAPSK = 0x0002;
export const WPS_AUTH_WPA = 0x0008;
export const WPS_AUTH_WPA2 = 0x0010;
export const WPS_AUTH_WPA2PSK = 0x0020;
export const WPS_AUTH_SAE = 0x0040;

export const WPS_ENCR_NONE = 0x0001;
export const WPS_ENCR_TKIP = 0x0004;
export const WPS_ENCR_AES = 0x0008;

export const WPS_RF_2GHZ = 0x01;
export const WPS_RF_5GHZ = 0x02;
export const WPS_RF_60GHZ = 0x04;
export const WPS_RF_6GHZ = 0x80; // NOT defined in WSC standard, local use only

function uci_band_to_rf_band(band) {
	switch (band) {
		case '2g': return WPS_RF_2GHZ;
		case '5g': return WPS_RF_5GHZ;
		case '6g': return WPS_RF_6GHZ;
		case '60g': return WPS_RF_60GHZ;
	}
}

function rf_band_ntoa(band) {
	switch (band) {
		case WPS_RF_2GHZ: return '2.4GHz';
		case WPS_RF_5GHZ: return '5GHz';
		case WPS_RF_6GHZ: return '6GHz';
		case WPS_RF_60GHZ: return '60GHz';
	}
}

const OPERATING_CLASSES = [
	// 2.4 GHz classes
	{ opc: 81, band: WPS_RF_2GHZ, channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] },
	{ opc: 82, band: WPS_RF_2GHZ, channels: [14] },
	{ opc: 83, band: WPS_RF_2GHZ, channels: [1, 2, 3, 4, 5, 6, 7, 8, 9], width: 40 },
	{ opc: 84, band: WPS_RF_2GHZ, channels: [5, 6, 7, 8, 9, 10, 11, 12, 13], width: 40 },

	// 5 GHz classes
	{ opc: 115, band: WPS_RF_5GHZ, channels: [36, 40, 44, 48] },
	{ opc: 116, band: WPS_RF_5GHZ, channels: [36, 44], width: 40 },
	{ opc: 117, band: WPS_RF_5GHZ, channels: [40, 48], width: 40 },
	{ opc: 118, band: WPS_RF_5GHZ, channels: [52, 56, 60, 64], dfs: true },
	{ opc: 119, band: WPS_RF_5GHZ, channels: [52, 60], width: 40, dfs: true },
	{ opc: 120, band: WPS_RF_5GHZ, channels: [56, 64], width: 40, dfs: true },
	{ opc: 121, band: WPS_RF_5GHZ, channels: [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140], dfs: true },
	{ opc: 122, band: WPS_RF_5GHZ, channels: [100, 108, 116, 124, 132, 140], width: 40, dfs: true },
	{ opc: 123, band: WPS_RF_5GHZ, channels: [104, 112, 120, 128, 136], width: 40, dfs: true },
	{ opc: 124, band: WPS_RF_5GHZ, channels: [149, 153, 157, 161, 165] },
	{ opc: 125, band: WPS_RF_5GHZ, channels: [149, 157], width: 40 },
	{ opc: 126, band: WPS_RF_5GHZ, channels: [153, 161], width: 40 },
	{ opc: 127, band: WPS_RF_5GHZ, channels: [36, 40, 44, 48, 52, 56, 60, 64], width: 80, dfs: true },
	{ opc: 128, band: WPS_RF_5GHZ, channels: [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140], width: 80, dfs: true },
	{ opc: 129, band: WPS_RF_5GHZ, channels: [149, 153, 157, 161], width: 80 },
	{ opc: 130, band: WPS_RF_5GHZ, channels: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140], width: 160, dfs: true },

	// 6 GHz classes
	{ opc: 131, band: WPS_RF_6GHZ, channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29] },
	{ opc: 132, band: WPS_RF_6GHZ, channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13], width: 40 },
	{ opc: 133, band: WPS_RF_6GHZ, channels: [1, 2, 3, 4, 5, 6, 7], width: 80 },
	{ opc: 134, band: WPS_RF_6GHZ, channels: [1, 2, 3], width: 160 },
	{ opc: 135, band: WPS_RF_6GHZ, channels: [1], width: 320 },

	// 60 GHz classes (IEEE 802.11ad/ay)
	{ opc: 180, band: WPS_RF_60GHZ, channels: [1], width: 2160 },
	{ opc: 181, band: WPS_RF_60GHZ, channels: [2], width: 2160 },
	{ opc: 182, band: WPS_RF_60GHZ, channels: [3], width: 2160 },
	{ opc: 183, band: WPS_RF_60GHZ, channels: [4], width: 2160 },

	// EDMG Channels (802.11ay)
	{ opc: 184, band: WPS_RF_60GHZ, channels: [9], width: 4320, edmg: true },
	{ opc: 185, band: WPS_RF_60GHZ, channels: [10], width: 4320, edmg: true },
	{ opc: 186, band: WPS_RF_60GHZ, channels: [11], width: 4320, edmg: true },
	{ opc: 187, band: WPS_RF_60GHZ, channels: [12], width: 6480, edmg: true },
	{ opc: 188, band: WPS_RF_60GHZ, channels: [13], width: 6480, edmg: true },
	{ opc: 189, band: WPS_RF_60GHZ, channels: [14], width: 8640, edmg: true }
];

function frequencyToBand(frequency) {
	if (frequency >= 2412 && frequency <= 2484)
		return WPS_RF_2GHZ;
	else if (frequency >= 4910 && frequency <= 4980)
		return WPS_RF_5GHZ;
	else if (frequency >= 5170 && frequency <= 5835)
		return WPS_RF_5GHZ;
	else if (frequency >= 5925 && frequency <= 7125)
		return WPS_RF_6GHZ;
	else if (frequency >= 57000 && frequency <= 71000)
		return WPS_RF_60GHZ;
}

function frequencyToChannel(frequency) {
	if (frequency == 2484)
		return 14;
	else if (frequency == 5935)
		return 2;
	else if (frequency < 2484)
		return (frequency - 2407) / 5;
	else if (frequency >= 4910 && frequency <= 4980)
		return (frequency - 4000) / 5;
	else if (frequency < 5950)
		return (frequency - 5000) / 5;
	else if (frequency <= 45000)
		return (frequency - 5950) / 5;
	else if (frequency >= 58320 && frequency <= 74520)
		return (frequency - 56160) / 2160;
}

function channelToFrequency(band, channel) {
	if (band == WPS_RF_2GHZ && channel == 14)
		return 2484;
	else if (band == WPS_RF_6GHZ && channel == 2)
		return 5935;
	else if (band == WPS_RF_2GHZ && channel >= 1 && channel <= 13)
		return 2407 + channel * 5;
	else if (band == WPS_RF_5GHZ && channel >= 184 && channel <= 196)
		return 4000 + channel * 5;
	else if (band == WPS_RF_5GHZ && channel >= 32 && channel <= 189)
		return 5000 + channel * 5;
	else if (band == WPS_RF_6GHZ && channel >= 1 && channel <= 233)
		return 5950 + channel * 5;
	else if (band == WPS_RF_60GHZ && channel >= 1 && channel <= 8)
		return 56160 + channel * 2160;
}

/**
 * Determine supported channel widths based on capabilities
 *
 * @param {object} phy - NL80211_CMD_GET_WIPHY reply message
 * @returns {number[]} Array of supported widths in MHz
 */
function getSupportedWidths(phy) {
	const widths = [];

	for (let band in phy.wiphy_bands) {
		const ht_capa = band?.ht_capa ?? 0;
		const vht_capa = band?.vht_capa ?? 0;

		if (ht_capa & (1 << 1))
			push(widths, 40);

		if (vht_capa)
			push(widths, 40, 80);

		if (((vht_capa >> 2) & 3) in [1, 2])
			push(widths, 160);

		for (let iftype_data in band?.iftype_data) {
			const he_capa = iftype_data.he_cap_phy?.[0] ?? 0;

			if (he_capa & (1 << 1))
				push(widths, 40);

			if (he_capa & (1 << 2))
				push(widths, 40, 80);

			if (he_capa & (1 << 3))
				push(widths, 160);

			if (he_capa & (1 << 4))
				push(widths, 160);
		}
	}

	return sort(uniq(widths));
}

/**
 * Determine supported operating classes based on phy capabilities
 *
 * @param {object} phy - NL80211_CMD_GET_WIPHY reply message
 * @param {integer} [radio_band] - The RF band the radio is tuned to
 * @returns {OperatingClass[]} Array of supported OperatingClass objects
 */
function getSupportedOperatingClasses(phy, radio_band) {
	const supportedClasses = [];
	const supportedWidths = getSupportedWidths(phy);

	for (let opClass in OPERATING_CLASSES) {
		if (radio_band !== null && opClass.band !== radio_band)
			continue;

		if (!((opClass.width ?? 20) in supportedWidths))
			continue;

		let maxTxPower = 2000;
		let disabledChannels = [];
		let matchingFrequencies = 0;

		for (let available_band in phy.wiphy_bands) {
			for (let available_freq in available_band?.freqs) {
				if (available_freq.no_80mhz && opClass.width == 80)
					continue;

				if (available_freq.no_160mhz && opClass.width == 160)
					continue;

				if (available_freq.no_ht40_minus && available_freq.no_ht40_plus && opClass.width == 40)
					continue;

				const band = frequencyToBand(available_freq.freq);
				const channel = frequencyToChannel(available_freq.freq);

				if (band != opClass.band)
					continue;

				if (!(channel in opClass.channels))
					continue;

				if (available_freq.disabled || available_freq.no_ir) {
					push(disabledChannels, channel);
					continue;
				}

				matchingFrequencies++;
				maxTxPower = max(maxTxPower, available_freq.max_tx_power);
			}
		}

		if (matchingFrequencies > 0)
			push(supportedClasses, {
				opclass: opClass.opc,

				// EasyMesh Spec v5, section 17.2.7 AP Radio Basic Capabilities
				// TLV format states that the Max TX power EIRP field is coded
				// as 2's complement signed integer in units of decibels
				// relative to 1 mW (dBm). Since we can't possible see any
				// negative values here, simply cap to the range 0..127
				max_txpower_eirp: min(maxTxPower / 100, 127),

				statically_non_operable_channels: disabledChannels
			});
	}

	return supportedClasses;
}

const IRadio = {
	deriveUUID: function () {
		const bytes = this.address ? unpack("6B", hexdec(this.address, ":")) : [this.info?.wiphy ?? 0];

		let h = 0;

		for (let byte in bytes)
			h = (h << 8) | byte;

		h ^= this.band;

		return [
			(h >> 32) & 0xff,
			(h >> 24) & 0xff,
			(h >> 16) & 0xff,
			(h >> 8) & 0xff,
			h & 0xff,
			0x40, // Version 4
			((h >> 8) & 0x3f) | 0x80, // Variant bits
			h & 0xff,
			(h >> 40) & 0xff,
			(h >> 32) & 0xff,
			(h >> 24) & 0xff,
			(h >> 16) & 0xff,
			(h >> 8) & 0xff,
			h & 0xff,
			this.band & 0xff,
			(this.band >> 8) & 0xff
		];
	},

	getSupportedOperatingClasses: function () {
		return getSupportedOperatingClasses(this.info, this.band);
	},

	getBasicCapabilities: function () {
		const caps = {
			radio_unique_identifier: this.address,
			opclasses_supported: getSupportedOperatingClasses(this.info, this.band),
			max_bss_supported: 1
		};

		for (let interfaceCombination in this.info?.interface_combinations) {
			let max_bss = 0;

			for (let combinationLimit in interfaceCombination.limits)
				if ('ap' in combinationLimit.types)
					max_bss = max(max_bss, combinationLimit.max);

			caps.max_bss_supported = min(max(caps.max_bss_supported, min(max_bss, interfaceCombination.maxnum)), 255);
		}

		return caps;
	},

	getHTCapabilities: function () {
		for (let band in this.info?.wiphy_bands) {
			for (let freq in band?.freqs) {
				const rf_band = frequencyToBand(freq.freq);

				if (rf_band === null)
					continue;

				if (rf_band !== this.band)
					break;

				if (!band.ht_capa)
					return null;

				let rx_streams = 1;
				let tx_streams = 1;

				if (band.ht_mcs_set) {
					for (let idx in band.ht_mcs_set.rx_mcs_indexes) {
						if (idx >= 8)
							rx_streams = 2;
						else if (idx >= 16)
							rx_streams = 3;
						else if (idx >= 24)
							rx_streams = 4;
					}

					if (band.ht_mcs_set.tx_rx_mcs_set_equal)
						tx_streams = rx_streams;
					else
						tx_streams = band.ht_mcs_set.tx_max_spatial_streams;
				}

				return {
					radio_unique_identifier: this.address,
					ht_support_40mhz: !!(band.ht_capa & 0b00000010),
					short_gi_support_20mhz: !!(band.ht_capa & 0b00100000),
					short_gi_support_40mhz: !!(band.ht_capa & 0b01000000),
					max_supported_rx_spatial_streams: rx_streams,
					max_supported_tx_spatial_streams: tx_streams
				};
			}
		}

		return null;
	},

	getVHTCapabilities: function () {
		for (let band in this.info?.wiphy_bands) {
			for (let freq in band?.freqs) {
				const rf_band = frequencyToBand(freq.freq);

				if (rf_band === null)
					continue;

				if (rf_band !== this.band)
					break;

				if (!band.vht_capa)
					return null;

				const supp_chan_width = (band.vht_capa >> 2) & 3;

				let supported_vht_rx_mcs = 0;
				let supported_vht_tx_mcs = 0;

				let max_rx_ss = 1;
				let max_tx_ss = 1;

				for (let i = 0; i < 8; i++) {
					const set_rx = band.vht_mcs_set?.rx_mcs_set?.[i];
					const max_rx = set_rx?.mcs_indexes?.[-1];

					const set_tx = band.vht_mcs_set?.tx_mcs_set?.[i];
					const max_tx = set_tx?.mcs_indexes?.[-1];

					if (max_rx == 7)
						supported_vht_rx_mcs |= (0 << (i * 2));
					else if (max_rx == 8)
						supported_vht_rx_mcs |= (1 << (i * 2));
					else if (max_rx == 9)
						supported_vht_rx_mcs |= (2 << (i * 2));
					else
						supported_vht_rx_mcs |= (3 << (i * 2));

					if (max_tx == 7)
						supported_vht_tx_mcs |= (0 << (i * 2));
					else if (max_tx == 8)
						supported_vht_tx_mcs |= (1 << (i * 2));
					else if (max_tx == 9)
						supported_vht_tx_mcs |= (2 << (i * 2));
					else
						supported_vht_tx_mcs |= (3 << (i * 2));

					max_rx_ss = max(max_rx_ss, set_rx?.streams);
					max_tx_ss = max(max_tx_ss, set_tx?.streams);
				}

				return {
					radio_unique_identifier: this.address,
					vht_support_160mhz: (supp_chan_width >= 1),
					vht_support_8080mhz: (supp_chan_width >= 2),
					su_beamformer_capable: !!(band.vht_capa & 0x00000800),
					mu_beamformer_capable: !!(band.vht_capa & 0x00080000),
					short_gi_support_80mhz: !!(band.vht_capa & 0x00000020),
					short_gi_support_160mhz_8080mhz: !!(band.vht_capa & 0x00000040),
					max_supported_rx_spatial_streams: max_rx_ss - 1,
					max_supported_tx_spatial_streams: max_tx_ss - 1,
					supported_vht_rx_mcs,
					supported_vht_tx_mcs,
				};
			}
		}

		return null;
	},

	getHECapabilities: function (sta_mode) {
		for (let band in this.info?.wiphy_bands) {
			for (let freq in band?.freqs) {
				const rf_band = frequencyToBand(freq.freq);

				if (rf_band === null)
					continue;

				if (rf_band !== this.band)
					break;

				let he_cap_phy;
				let he_cap_mcs_set;

				for (let iftype_caps in band.iftype_data) {
					if (iftype_caps.iftypes?.[sta_mode ? 'managed' : 'ap']) {
						he_cap_phy = iftype_caps.he_cap_phy;
						he_cap_mcs_set = iftype_caps.he_cap_mcs_set;
						break;
					}
				}

				if (!he_cap_phy)
					return null;

				const supported_mcs = buffer();

				let max_rx_ss = 1;
				let max_tx_ss = 1;

				let he_support_160mhz = false;
				let he_support_8080mhz = false;

				for (let per_bw_sets in he_cap_mcs_set) {
					let rx_mcses = 0;
					let tx_mcses = 0;

					for (let i = 0; i < 8; i++) {
						const set_rx = per_bw_sets?.rx_mcs_set?.[i];
						const max_rx = set_rx?.mcs_indexes?.[-1];

						const set_tx = per_bw_sets?.tx_mcs_set?.[i];
						const max_tx = set_tx?.mcs_indexes?.[-1];

						if (max_rx == 7)
							rx_mcses |= (0 << (i * 2));
						else if (max_rx == 9)
							rx_mcses |= (1 << (i * 2));
						else if (max_rx == 11)
							rx_mcses |= (2 << (i * 2));
						else
							rx_mcses |= (3 << (i * 2));

						if (max_tx == 7)
							tx_mcses |= (0 << (i * 2));
						else if (max_tx == 9)
							tx_mcses |= (1 << (i * 2));
						else if (max_tx == 11)
							tx_mcses |= (2 << (i * 2));
						else
							tx_mcses |= (3 << (i * 2));

						max_rx_ss = max(max_rx_ss, set_rx?.streams);
						max_tx_ss = max(max_tx_ss, set_tx?.streams);
					}

					supported_mcs.put('!HH', rx_mcses, tx_mcses);

					if (per_bw_sets.bandwidth == 160)
						he_support_160mhz = true;
					else if (per_bw_sets.bandwidth == 8080)
						he_support_8080mhz = true;
				}

				return {
					radio_unique_identifier: this.address,
					supported_he_mcs: supported_mcs.pull(),
					max_supported_rx_spatial_streams: max_rx_ss - 1,
					max_supported_tx_spatial_streams: max_tx_ss - 1,
					he_support_160mhz,
					he_support_8080mhz,
					su_beamformer_capable: !!(he_cap_phy[4] & 0b10000000),
					mu_beamformer_capable: !!(he_cap_phy[5] & 0b00000010),
					ul_mu_mimo_capable: !!(he_cap_phy[3] & 0b11000000),

					/* FIXME: are these supported by mac80211 at all? */
					ul_mu_mimo_ofdma_capable: false,
					dl_mu_mimo_ofdma_capable: false,
					ul_ofdma_capable: false,
					dl_ofdma_capable: false
				};
			}
		}

		return null;
	},

	inferWSCAuthenticationSuites: function () {
		let auth_suites = WPS_AUTH_OPEN;

		for (let suite in this.info?.cipher_suites) {
			switch (suite) {
				//case 0x000FAC01:
				//case 0x000FAC05:
				//	auth_suites |= WPS_AUTH_WEP;
				//	break;
				case 0x000FAC02:
					auth_suites |= WPS_AUTH_WPA | WPS_AUTH_WPAPSK;
					break;
				case 0x000FAC04:
					auth_suites |= WPS_AUTH_WPA2 | WPS_AUTH_WPA2PSK;
					break;
				case 0x000FAC08:
				case 0x000FAC09:
				case 0x000FAC0A:
					auth_suites |= WPS_AUTH_SAE;
					break;
			}
		}

		return auth_suites;
	},

	inferWSCEncryptionTypes: function () {
		let encryption_types = WPS_ENCR_NONE;

		for (let suite in this.info?.cipher_suites) {
			switch (suite) {
				//case 0x000FAC01:
				//	encryption_types |= WPS_ENCR_WEP40;
				//	break;
				case 0x000FAC02:
					encryption_types |= WPS_ENCR_TKIP;
					break;
				case 0x000FAC04:
				case 0x000FAC08:
				case 0x000FAC09:
				case 0x000FAC0A:
					encryption_types |= WPS_ENCR_AES;
					break;
				//case 0x000FAC05:
				//	encryption_types |= WPS_ENCR_WEP104;
				//	break;
			}
		}

		return encryption_types;
	},

	inferWSCRFBands: function () {
		let bands = 0;

		for (let band in this.info?.wiphy_bands) {
			for (let freq in band?.freqs) {
				const rf_band = frequencyToBand(freq.freq);

				if (rf_band) {
					bands |= rf_band;
					break;
				}
			}
		}

		return bands;
	},

	getBackhaulStationAddress: function () {
		for (let radio_name, radio_state in ubus.call('network.wireless', 'status')) {
			if (radio_name != this.config)
				continue;

			for (let iface in radio_state?.interfaces)
				if (iface.config?.mode == 'sta' && iface.config?.multi_ap == '1')
					return readfile(`/sys/class/net/${iface.ifname}/address`, 17);
		}
	}
};

const IWireless = {
	radios: [],

	observeAssociationEvents: function () {
		const self = this;

		this.hostapdSubscriber = ubus.subscriber(msg => {
			if (msg.type == 'assoc' || msg.type == 'disassoc') {
				const radio = self.lookupRadioByIfname(msg.data.ifname);

				if (radio) {
					events.dispatch('wireless.association', {
						radio,
						ap_address: readfile(`/sys/class/net/${msg.data.ifname}/address`, 17),
						sta_address: msg.data.address,
						associated: (msg.type == 'assoc'),
					});
				}
			}
		}, null, ['hostapd.*']);
	},

	addRadio: function (name) {
		let _uci = cursor();

		let config = _uci.get_all('wireless', name);
		if (config && config['.type'] != 'wifi-device') {
			log.warn(`Invalid radio config section ${name}`);
			return;
		}

		let phyname = name;
		if (config) {
			phyname = find_phy(config);
			if (!phyname) {
				log.warn(`Could not find phy for radio config ${name}`);
				return;
			}
		} else {
			/* lookup corresponding uci wifi-device section for phy */
			cursor().foreach('wireless', 'wifi-device', wifi => {
				if (find_phy(wifi) == phyname)
					config = wifi;

			});
		}

		let existing = filter(this.radios, radio => radio.phyname == phyname)[0];
		if (existing != null) {
			log.warn(`Radio phy '${phyname}' already present`);
			return existing;
		}

		let idx = readfile(`/sys/class/ieee80211/${phyname}/index`);
		if (idx == null) {
			log.warn(`Radio phy '${phyname}' not present on system`);
			return null;
		}

		let phy = wlrequest(wlconst.NL80211_CMD_GET_WIPHY, 0, {
			wiphy: +idx,
			split_wiphy_dump: true
		});

		if (phy == null) {
			log.warn(`Error querying phy '${phyname}' capabilities: ${wlerror()}`);
			return null;
		}

		let supported_bands = [];

		for (let band in phy?.wiphy_bands) {
			for (let freq in band?.freqs) {
				const rf_band = frequencyToBand(freq.freq);

				if (rf_band) {
					push(supported_bands, rf_band);
					break;
				}
			}
		}

		supported_bands = sort(supported_bands);
		const rf_band = uci_band_to_rf_band(config.band);
		let band = (rf_band in supported_bands) ? rf_band : null;

		let radio = proto({
			phyname,
			index: +idx,
			info: phy,
			band,
			config: config['.name'],
			address: readfile(`/sys/class/ieee80211/${phyname}/macaddress`, 17)
		}, IRadio);


		/* if no explicit band is configured on the radio, intelligently guess default band */
		if (radio.band == null) {
			let used_bands = map(this.radios, radio => radio.band);

			radio.band = filter(supported_bands, band => !(band in used_bands))[0] ?? supported_bands[0];
			log.warn(`No band configured for radio phy '${phyname}' - guessing ${radio.band}`);
		}

		log.info(`Using logical radio '${radio.config ?? 'unknown'}', phy '${phyname}', band ${rf_band_ntoa(radio.band) ?? 'unknown'}`);
		push(this.radios, radio);

		return radio;
	},

	lookupRadiosByBand: function (band) {
		return filter(this.radios, radio => matchBand(radio.band, band));
	},

	lookupRadioByIfname: function (ifname) {
		const phyidx = readfile(`/sys/class/net/${ifname}/phy80211/index`);

		for (let radio in this.radios)
			if (phyidx != null && radio.index == +phyidx)
				return radio;
	},

	lookupRadioByAddress: function (address) {
		for (let radio in this.radios)
			if (address != null && radio.address == address)
				return radio;
	},

	lookupOperatingClass: function (opclass) {
		for (let opc in OPERATING_CLASSES)
			if (opc.opc === opclass)
				return opc;
	},

	lookupFrequenciesByOperatingClass: function (opclass) {
		for (let opc in OPERATING_CLASSES) {
			if (opc.opc === opclass) {
				const freqs = [];

				for (let channel in opc.channels) {
					const freq = channelToFrequency(opc.band, channel);

					if (freq != null)
						push(freqs, freq);
				}

				return freqs;
			}
		}
	},

	lookupOperatingClassChannelByFrequency: function (frequency, opclass) {
		const band = frequencyToBand(frequency);
		const channel = frequencyToChannel(frequency);

		if (band != null && channel != null) {
			for (let opc in OPERATING_CLASSES) {
				if (opclass != null && opclass !== opc.opc)
					continue;

				if (opc.band == band && channel in opc.channels)
					return [opc.opc, channel];
			}
		}
	},

	channelToFrequency: channelToFrequency,
	frequencyToChannel: frequencyToChannel,
};

IWireless.observeAssociationEvents();

export default IWireless;
