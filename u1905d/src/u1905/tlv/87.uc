import { 'request' as wlreq, 'const' as wlconst } from 'nl80211';
import { pack, unpack } from 'struct';
import { readfile } from 'fs';
import utils from 'u1905.utils';

export default {
	type: 0x87,
	name: 'AP VHT Capabilities',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len != 12)
			return null;

		let radio_unique_id = utils.ether_ntoa(payload, 0);
		let val = unpack('!HHBB', payload, 6);

		let vht_tx_mcs_supported = {};
		let vht_rx_mcs_supported = {};

		for (let i = 0; i < 16; i += 2) {
			let ss = `${ i / 2 + 1 }_ss`;

			switch ((val[0] >> i) & 0b11) {
			case 0: vht_tx_mcs_supported[ss] = [ 0, 1, 2, 3, 4, 5, 6, 7 ]; break;
			case 1: vht_tx_mcs_supported[ss] = [ 0, 1, 2, 3, 4, 5, 6, 7, 8 ]; break;
			case 2: vht_tx_mcs_supported[ss] = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 ]; break;
			}

			switch ((val[1] >> i) & 0b11) {
			case 0: vht_rx_mcs_supported[ss] = [ 0, 1, 2, 3, 4, 5, 6, 7 ]; break;
			case 1: vht_rx_mcs_supported[ss] = [ 0, 1, 2, 3, 4, 5, 6, 7, 8 ]; break;
			case 2: vht_rx_mcs_supported[ss] = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 ]; break;
			}
		}

		return {
			radio_unique_id,
			vht_tx_mcs_supported,
			vht_rx_mcs_supported,
			max_tx_nss: 1 + ((val[2] >> 5) & 0b111),
			max_rx_nss: 1 + ((val[2] >> 2) & 0b111),
			short_gi_80mhz: !!(val[2] & 0b00000010),
			short_gi_160mhz: !!(val[2] & 0b00000001),
			vht_8080mhz: !!(val[3] & 0b10000000),
			vht_160mhz: !!(val[3] & 0b01000000),
			su_beamformer: !!(val[3] & 0b00100000),
			mu_beamformer: !!(val[3] & 0b00010000)
		};
	},

	/** @param string[] radio names */
	encode: (phyname) => {
		const phyidx = readfile(`/sys/class/ieee80211/${phyname}/index`);

		if (!phyidx)
			return null;

		const info = wlreq(wlconst.NL80211_CMD_GET_WIPHY, 0, { wiphy: +phyidx, split_wiphy_dump: true });

		if (!info)
			return null;

		const mac_address = trim(readfile(`/sys/class/ieee80211/${phyname}/macaddress`)) ?? sprintf('00:00:00:00:00:%02x', +phyidx % 256);

		let vht_tx_mcs_supported = 0;
		let vht_rx_mcs_supported = 0;
		let max_tx_nss = 1;
		let max_rx_nss = 1;
		let vht_160mhz = false;
		let vht_8080mhz = false;
		let short_gi_80mhz = false;
		let short_gi_160mhz = false;
		let su_beamformer = false;
		let mu_beamformer = false;

		for (let band in info?.wiphy_bands) {
			for (let set in band?.vht_mcs_set?.tx_mcs_set) {
				if (set.streams > max_tx_nss)
					max_tx_nss = set.streams;

				let v;
				switch (length(set.mcs_indexes)) {
				case 8:  v = 0; break;
				case 9:  v = 1; break;
				case 10: v = 2; break;
				default: v = 3; break;
				}

				vht_tx_mcs_supported |= (v << ((set.streams - 1) * 2));
			}

			for (let set in band?.vht_mcs_set?.rx_mcs_set) {
				if (set.streams > max_rx_nss)
					max_rx_nss = set.streams;

				let v;
				switch (length(set.mcs_indexes)) {
				case 8:  v = 0; break;
				case 9:  v = 1; break;
				case 10: v = 2; break;
				default: v = 3; break;
				}

				vht_rx_mcs_supported |= (v << ((set.streams - 1) * 2));
			}

			const capabilities = band?.vht_capa ?? 0;

			if (capabilities & 0b00000000000000100000)
				short_gi_80mhz = true;

			if (capabilities & 0b00000000000001000000)
				short_gi_160mhz = true;

			if (capabilities & 0b00000000100000000000)
				su_beamformer = true;

			if (capabilities & 0b10000000000000000000)
				mu_beamformer = true;

			switch ((((capabilities >> 2) & 3) << 4) | ((capabilities >> 30) & 3)) {
			case 0x01:
			case 0x10:
				vht_160mhz = true;
				break;

			case 0x02:
			case 0x03:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x14:
			case 0x20:
			case 0x23:
				vht_160mhz = true;
				vht_8080mhz = true;
				break;
			}
		}

		return pack('!6sHHBB',
			utils.ether_aton(mac_address),
			vht_tx_mcs_supported,
			vht_rx_mcs_supported,
			((((max_tx_nss - 1) & 0b111) << 5) |
			 (((max_rx_nss - 1) & 0b111) << 2) |
			 (short_gi_80mhz << 1) |
			 (short_gi_160mhz << 0)),
			((vht_8080mhz << 7) |
			 (vht_160mhz << 6) |
			 (su_beamformer << 5) |
			 (mu_beamformer << 4)));
	},
};
