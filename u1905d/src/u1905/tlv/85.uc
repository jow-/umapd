import { 'request' as wlreq, 'const' as wlconst } from 'nl80211';
import { pack, unpack } from 'struct';
import { readfile } from 'fs';
import utils from 'u1905.utils';

const WIDTH_20   = 0;
const WIDTH_40M  = 1;
const WIDTH_40P  = 2;
const WIDTH_80   = 3;
const WIDTH_160  = 4;
const WIDTH_8080 = 5;

/* frequency+width to op class mapping table:
 * from MHz, to MHz, 20MHz/40+/40-/80/160/80+80MHz width class */
const op_class_mapping = [
	/* 2.4GHz, channels 1..13 */
	 2412,  2472,  81,  83,  84,   0,   0,   0,

	/* 2.4GHz, channel 14 */
	 2484,  2484,  82,   0,   0,   0,   0,   0,

	/* 5 GHz, channels 36..48 */
	 5260,  5320, 115, 116, 117, 128, 129, 130,

	/* 5 GHz, channels 52..64 */
	 5260,  5320, 118, 119, 120, 128, 129, 130,

	/* 5 GHz, channels 100..144 */
	 5500,  5720, 121, 122, 123, 128, 129, 130,

	/* 5 GHz, channels 149..161 */
	 5745,  5805, 124, 126, 127, 128, 129, 130,

	/* 5 GHz, channels 165..169 */
	 5810,  5845, 125, 126, 127, 128, 129, 130,

	/* 56.16 GHz, channel 1..4 */
	58320, 69120, 180,   0,   0,   0,   0,   0
];

function freq_to_channel(freq) {
	if (freq < 1000)
		return null;

	if (freq == 2484)
		return 14;
	else if (freq == 5935)
		return 2;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq < 5950)
		return (freq - 5000) / 5;
	else if (freq <= 45000)
		return (freq - 5950) / 5;
	else if (freq >= 58320 && freq <= 70200)
		return (freq - 56160) / 2160;

	return null;
}

function band_to_channel_widths(band) {
	let chan_widths = (1 << WIDTH_20);
	let ht_cap = band?.ht_capa ?? 0;
	let vht_cap = band?.vht_capa ?? 0;
	let he_cap = filter(band?.iftype_data, e => e.iftypes?.ap)?.[0]?.he_cap_phy?.[0] ?? 0;

	if (ht_cap & 0b00000001)
		chan_widths |= (1 << WIDTH_40M) | (1 << WIDTH_40P);

	if (vht_cap > 0)
		chan_widths |= (1 << WIDTH_40M) | (1 << WIDTH_40P) | (1 << WIDTH_80);

	switch ((vht_cap >> 2) & 3) {
	case 1: chan_widths |= (1 << WIDTH_160);  break;
	case 2: chan_widths |= (1 << WIDTH_8080); break;
	}

	if (he_cap & 0b00000010)
		chan_widths |= (1 << WIDTH_40M) | (1 << WIDTH_40P);

	if (he_cap & 0b00000100)
		chan_widths |= (1 << WIDTH_40M) | (1 << WIDTH_40P) | (1 << WIDTH_80);

	if (he_cap & 0b00001000)
		chan_widths |= (1 << WIDTH_160);

	if (he_cap & 0b00010000)
		chan_widths |= (1 << WIDTH_160) | (1 << WIDTH_8080);

	return chan_widths;
}


export default {
	type: 0x85,
	name: 'AP Radio Basic Capabilities',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 8)
			return null;

		let radio_unique_id = utils.ether_ntoa(payload, 0);
		let max_bss_supported = ord(payload, 6);
		let num_op_classes = ord(payload, 7);

		let res = {
			radio_unique_id,
			max_bss_supported,
			op_classes_supported: []
		};

		for (let off = 8; off < len && num_op_classes > 0; num_op_classes--) {
			let values = unpack("BbB", payload, off);

			push(res.op_classes_supported, {
				op_class: values[0],
				max_eirp: values[1],
				non_operable_channels: []
			});

			for (off += 3; values[2] > 0 && off < len; off++, values[2]--)
				push(res.op_classes_supported[-1].non_operable_channels, ord(payload, off));
		}

		/* truncated TLV or trailing garbage */
		if (num_op_classes > 0 || off < len)
			return null;

		return res;
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

		let max_bss_supported = 1;

		for (let comb in info?.interface_combinations) {
			max_bss_supported = comb.maxnum;

			for (let limit in comb?.limits) {
				if (limit.types?.ap && limit.max)
					max_bss_supported = limit.max;
			}
		}

		const op_classes = {};

		for (let band in info?.wiphy_bands) {
			let channel_widths = band_to_channel_widths(band);

			for (let freq in band?.freqs) {
				for (let width = WIDTH_20; width <= WIDTH_8080; width++) {
					if (!(channel_widths & (1 << width)))
						continue;

					if ((width == WIDTH_40M && freq.no_40_minus) ||
					    (width == WIDTH_40P && freq.no_40_plus) ||
					    (width == WIDTH_80 && freq.no_80mhz) ||
					    (width == WIDTH_160 && freq.no_160mhz) ||
					    (width == WIDTH_8080 && freq.no_160mhz))
						continue;

					for (let i = 0; i < length(op_class_mapping); i += 8) {
						if (freq.freq < op_class_mapping[i + 0])
							continue;

						if (freq.freq > op_class_mapping[i + 1])
							continue;

						if (op_class_mapping[i + 2 + width] == 0)
							continue;

						let classid = op_class_mapping[i + 2 + width];
						let channel = freq_to_channel(freq.freq);

						if (classid == 0 || channel == 0)
							continue;

						op_classes[classid] ??= [ 10000 ];

						if (freq.max_tx_power < op_classes[classid][0])
							op_classes[classid][0] = freq.max_tx_power;

						if (freq.disabled)
							push(op_classes[classid], channel);
					}
				}
			}
		}

		let fmt = '6sBB';
		let val = [ utils.ether_aton(mac_address), max_bss_supported, length(op_classes) ];

		for (let classid in sort(keys(op_classes))) {
			fmt += 'BbB';
			push(val, +classid, op_classes[classid][0] / 100, length(op_classes[classid]) - 1);

			for (let i = 1; i < length(op_classes[classid]); i++) {
				fmt += 'B';
				push(val, op_classes[classid][i]);
			}
		}

		return pack(fmt, ...val);
	},
};
