import { pack, unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

function encode_local_interface(i1905lif) {
	let media_info = "";
	let info = i1905lif.getRuntimeInformation();

	if (!info)
		return null;

	if (info.wifi) {
		let role = 0, chanbw = 0, chan1 = 0, chan2 = 0;

		switch (info.wifi.interface.iftype ?? 0) {
		case 1: /* Ad-Hoc */
		case 2: /* Station */
		case 5: /* WDS */
		case 6: /* Monitor */
		case 7: /* Mesh Point */
		case 10: /* P2P Device */
		case 11: /* OCB */
		case 12: /* NAN */
			role = 0b01000000;
			break;

		case 3: /* AP */
		case 4: /* AP VLAN */
			role = 0b00000000;
			break;

		case 8: /* P2P Client */
			role = 0b10000000;
			break;

		case 9: /* P2P Go */
			role = 0b10010000;
			break;

		default: /* unspecified/unknown */
			role = 0b01000000;
			break;
		}

		switch (info.wifi.interface.channel_width ?? 0) {
		case 0: /* 20MHz NOHT */
		case 1: /* 20MHz */
		case 2: /* 40Mhz */
			chanbw = 0;
			break;

		case 3: /* 80MHz */
			chanbw = 1;
			break;

		case 4: /* 80+80MHz */
			chanbw = 3;
			break;

		case 5: /* 160MHz */
			chanbw = 2;
			break;

		case 6: /* 5MHz */
		case 7: /* 10MHz */
		case 8: /* 1MHz */
		case 9: /* 2MHz */
		case 10: /* 4MHz */
		case 11: /* 8MHz */
		case 12: /* 16MHz */
			chanbw = 0;
			break;
		}

		for (let band in info.wifi.phy.wiphy_bands) {
			for (let i, freq in band?.freqs) {
				if (freq.freq == info.wifi.interface.center_freq1)
					chan1 = i + 1;
				else if (freq.freq == info.wifi.interface.center_freq2)
					chan2 = i + 1;
			}
		}

		media_info = pack('!6sBBBB', hexdec(info.wifi.interface.mac, ':'), role, chanbw, chan1, chan2);
	}

	return pack('!6sHB*', hexdec(info.address, ':'), info.type, length(media_info), media_info);
}

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
	type: 0x03,
	name: 'Device information',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 7)
			return null;

		let res = {
			al_address: utils.ether_ntoa(payload),
			ifaces: []
		};

		let num_ifaces = ord(payload, 6);

		for (let i = 0, off = 7; i < num_ifaces && off < len; i++) {
			if (off + 9 > len)
				return null;

			let values = unpack('!HB', payload, off + 6);

			if (off + 9 + values[1] > len)
				return null;

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res.ifaces, {
				address: utils.ether_ntoa(payload, off),
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]]
			});

			if (values[1])
				res.ifaces[-1].media_info =
					decode_media_info(values[0], substr(payload, off + 9, values[1]));

			off += 9 + values[1];
		}

		return res;
	},

	/** @param i1905lif[] links
	 * @param string al_address */
	encode: (links, al_address) => {
		assert(length(links) <= 255, 'Too many interfaces for TLV');

		if (!length(links))
			return null;

		let fmt = '!6sB';
		let val = [ hexdec(al_address, ':'), 0 ];

		for (let i1905lif in links) {
			val[1]++;
			fmt += '*';
			push(val, encode_local_interface(i1905lif));
		}

		return pack(fmt, ...val);
	},
};
