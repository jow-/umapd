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
import { unpack } from 'struct';
import { cursor } from 'uci';

import utils from 'u1905.utils';
import log from 'u1905.log';

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
export const WPS_RF_6GHZ = 0x04;

const bandAliases = [
	[ utils.lookup_enum('IEEE1905_FREQUENCY_BAND', '802.11 2.4 GHz'), '2g',  '802.11 2.4 GHz' ],
	[ utils.lookup_enum('IEEE1905_FREQUENCY_BAND', '802.11 5 GHz'),   '5g',  '802.11 5 GHz'   ],
	[ utils.lookup_enum('IEEE1905_FREQUENCY_BAND', '802.11 60 GHz'),  '60g', '802.11 60 GHz'  ]
];

function matchBand(a, b) {
	for (aliases in bandAliases)
		if ((a in aliases) && (b in aliases))
			return true;

	return false;
}

const OPERATING_CLASSES = [
	// 2.4 GHz classes
	{ opc: 81, band: '2g', channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] },
	{ opc: 82, band: '2g', channels: [14] },
	{ opc: 83, band: '2g', channels: [1, 2, 3, 4, 5, 6, 7, 8, 9], width: 40 },
	{ opc: 84, band: '2g', channels: [5, 6, 7, 8, 9, 10, 11, 12, 13], width: 40 },

	// 5 GHz classes
	{ opc: 115, band: '5g', channels: [36, 40, 44, 48] },
	{ opc: 116, band: '5g', channels: [36, 44], width: 40 },
	{ opc: 117, band: '5g', channels: [40, 48], width: 40 },
	{ opc: 118, band: '5g', channels: [52, 56, 60, 64], dfs: true },
	{ opc: 119, band: '5g', channels: [52, 60], width: 40, dfs: true },
	{ opc: 120, band: '5g', channels: [56, 64], width: 40, dfs: true },
	{ opc: 121, band: '5g', channels: [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140], dfs: true },
	{ opc: 122, band: '5g', channels: [100, 108, 116, 124, 132, 140], width: 40, dfs: true },
	{ opc: 123, band: '5g', channels: [104, 112, 120, 128, 136], width: 40, dfs: true },
	{ opc: 124, band: '5g', channels: [149, 153, 157, 161, 165] },
	{ opc: 125, band: '5g', channels: [149, 157], width: 40 },
	{ opc: 126, band: '5g', channels: [153, 161], width: 40 },
	{ opc: 127, band: '5g', channels: [36, 40, 44, 48, 52, 56, 60, 64], width: 80, dfs: true },
	{ opc: 128, band: '5g', channels: [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140], width: 80, dfs: true },
	{ opc: 129, band: '5g', channels: [149, 153, 157, 161], width: 80 },
	{ opc: 130, band: '5g', channels: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140], width: 160, dfs: true },

	// 6 GHz classes
	{ opc: 131, band: '6g', channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29] },
	{ opc: 132, band: '6g', channels: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13], width: 40 },
	{ opc: 133, band: '6g', channels: [1, 2, 3, 4, 5, 6, 7], width: 80 },
	{ opc: 134, band: '6g', channels: [1, 2, 3], width: 160 },
	{ opc: 135, band: '6g', channels: [1], width: 320 },

	// 60 GHz classes (IEEE 802.11ad/ay)
	{ opc: 180, band: '60g', channels: [1], width: 2160 },
	{ opc: 181, band: '60g', channels: [2], width: 2160 },
	{ opc: 182, band: '60g', channels: [3], width: 2160 },
	{ opc: 183, band: '60g', channels: [4], width: 2160 },

	// EDMG Channels (802.11ay)
	{ opc: 184, band: '60g', channels: [9], width: 4320, edmg: true },
	{ opc: 185, band: '60g', channels: [10], width: 4320, edmg: true },
	{ opc: 186, band: '60g', channels: [11], width: 4320, edmg: true },
	{ opc: 187, band: '60g', channels: [12], width: 6480, edmg: true },
	{ opc: 188, band: '60g', channels: [13], width: 6480, edmg: true },
	{ opc: 189, band: '60g', channels: [14], width: 8640, edmg: true }
];

function frequencyToBand(frequency)
{
	if (frequency >= 2412 && frequency <= 2484)
		return '2g';
	else if (frequency >= 4910 && frequency <= 4980)
		return '5g';
	else if (frequency >= 5170 && frequency <= 5835)
		return '5g';
	else if (frequency >= 5925 && frequency <= 7125)
		return '6g';
	else if (frequency >= 57000 && frequency <= 71000)
		return '60g';
}

function frequencyToChannel(frequency)
{
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

function mbmToMw(dbm)
{
	const LOG10_MAGIC = 1.25892541179;
	let res = 1.0;
	let ip = dbm / 10;
	let fp = dbm % 10;

	for (let k = 0; k < ip; k++)
		res *= 10;

	for (let k = 0; k < fp; k++)
		res *= LOG10_MAGIC;

	return int(res);
}

/**
 * Determine supported channel widths based on capabilities
 *
 * @param {object} phy - NL80211_CMD_GET_WIPHY reply message
 * @returns {number[]} Array of supported widths in MHz
 */
function getSupportedWidths(phy)
{
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
 * @returns {OperatingClass[]} Array of supported OperatingClass objects
 */
function getSupportedOperatingClasses(phy)
{
	const supportedClasses = [];
	const supportedWidths = getSupportedWidths(phy);

	for (let opClass in OPERATING_CLASSES) {
		if (!((opClass.width ?? 20) in supportedWidths))
			continue;

		let maxTxPower = 2000;
		let disabledChannels = [];
		let matchingFrequencies = 0;

		for (let available_freq in phy.wiphy_bands?.freqs) {
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
			maxTxPower = max(maxTxPower, freq.max_tx_power);
		}

		if (matchingFrequencies > 0)
			push(supportedClasses, {
				opclass: opClass.opc,
				max_txpower_eirp: mbmToMw(maxTxPower),
				statically_non_operable_channels: disabledChannels
			});
	}

	return supportedClasses;
}

const IRadio = {
	getSupportedBandIndex: function() {
		for (let aliases in bandAliases)
			if (this.band in aliases)
				return aliases[0];

		return 0xff; // reserved
	},

	deriveUUID: function() {
		const bytes = this.address ? unpack("6B", hexdec(this.address, ":")) : [ this.info?.wiphy ?? 0 ];
		const bandidx = this.getSupportedBandIndex();

		let h = 0;

		for (let byte in bytes)
			h = (h << 8) | byte;

		h ^= bandidx;

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
			bandidx & 0xff,
			(bandidx >> 8) & 0xff
		];
	},

	getBasicCapabilities: function() {
		const caps = {
			radio_unique_identifier: this.address,
			opclasses_supported: getSupportedOperatingClasses(this.info),
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

	inferWSCAuthenticationSuites: function() {
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

	inferWSCEncryptionTypes: function() {
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

	inferWSCRFBands: function() {
		let bands = 0;

		for (let band in this.info?.wiphy_bands) {
			for (let freq in band?.freqs) {
				const band_name = frequencyToBand(freq.freq);

				if (band_name == '2g')      { bands |= WPS_RF_2GHZ; break; }
				else if (band_name == '5g') { bands |= WPS_RF_5GHZ; break; }
				else if (band_name == '6g') { bands |= WPS_RF_6GHZ; break; }
			}
		}

		return bands;
	},
};

export default {
	radios: [],

	addRadio: function(phyname) {
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
				const band_name = frequencyToBand(freq.freq);

				if (band_name) {
					push(supported_bands, band_name);
					break;
				}
			}
		}

		supported_bands = sort(supported_bands, (a, b) => int(a) - int(b));

		let radio = proto({
			phyname,
			index: idx,
			info: phy,
			address: readfile(`/sys/class/ieee80211/${phyname}/macaddress`, 17)
		}, IRadio);

		/* lookup corresponding uci wifi-device section for phy */
		cursor().foreach('wireless', 'wifi-device', wifi => {
			let wifi_phyname = trim(popen(`/usr/bin/iwinfo nl80211 phy '${wifi['.name']}'`, 'r').read('line'));
			if (wifi_phyname == phyname) {
				radio.config = wifi['.name'];
				radio.band = (wifi.band in supported_bands) ? wifi.band : null;
			}
		});

		/* if no explicit band is configured on the radio, intelligently guess default band */
		if (radio.band == null) {
			let used_bands = map(this.radios, radio => radio.band);

			radio.band = filter(supported_bands, band => !(band in used_bands))[0] ?? supported_bands[0];
			log.warn(`No band configured for radio phy '${phyname}' - guessing ${radio.band}`);
		}

		log.info(`Using logical radio '${radio.config ?? 'unknown'}', phy '${phyname}', band ${radio.band}`);
		push(this.radios, radio);

		return radio;
	},

	lookupRadiosByBand: function(band) {
		return filter(this.radios, radio => matchBand(radio.band, band));
	},

	lookupRadioByIfname: function(ifname) {
		const phyidx = readfile(`/sys/class/net/${ifname}/phy80211/index`);

		for (let radio in this.radios)
			if (phyidx != null && radio.index == +phyidx)
				return radio;
	},
};
