import { 'request' as wlreq, 'const' as wlconst } from 'nl80211';
import { pack, unpack } from 'struct';
import { readfile } from 'fs';
import utils from 'u1905.utils';

export default {
	type: 0x86,
	name: 'AP HT Capabilities',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len != 7)
			return null;

		let radio_unique_id = utils.ether_ntoa(payload, 0);
		let flags = ord(payload, 6);

		return {
			radio_unique_id,
			max_tx_nss: 1 + ((flags >> 6) & 0b11),
			max_rx_nss: 1 + ((flags >> 4) & 0b11),
			short_gi_20mhz: !!(flags & 0b00001000),
			short_gi_40mhz: !!(flags & 0b00000100),
			ht_40mhz: !!(flags & 0b00000010)
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

		let max_tx_nss = 1;
		let max_rx_nss = 1;
		let ht_40mhz = false;
		let short_gi_20mhz = false;
		let short_gi_40mhz = false;

		for (let band in info?.wiphy_bands) {
			let highest_idx = band?.ht_mcs_set?.rx_mcs_indexes?.[-1] ?? 0;

			if (highest_idx >= 24 && highest_idx <= 31 && max_rx_nss < 4)
				max_rx_nss = 4;
			else if (highest_idx >= 16 && highest_idx <= 23 && max_rx_nss < 3)
				max_rx_nss = 3;
			else if (highest_idx >= 8 && highest_idx <= 15 && max_rx_nss < 2)
				max_rx_nss = 2;

			if (max_tx_nss < band?.ht_mcs_set?.tx_max_spatial_streams)
				max_tx_nss = band.ht_mcs_set.tx_max_spatial_streams;

			let capabilities = band?.ht_capa ?? 0;

			if (capabilities & 0b00000010)
				ht_40mhz = true;

			if (capabilities & 0b00100000)
				short_gi_20mhz = true;

			if (capabilities & 0b01000000)
				short_gi_40mhz = true;
		}

		return pack('6sB',
			utils.ether_aton(mac_address),
			(((max_tx_nss - 1) & 0b11) << 6) | (((max_rx_nss - 1) & 0b11) << 4) |
			 (short_gi_20mhz << 3) | (short_gi_40mhz << 2) | (ht_40mhz << 1));
	},
};
