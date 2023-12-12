import { pack, unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x0a,
	name: 'Receiver link metric',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len <= 12 || ((len - 12) % 23))
			return null;

		let res = {
			al_address: utils.ether_ntoa(payload, 0),
			neighbor_al_address: utils.ether_ntoa(payload, 6),
			links: []
		};

		for (let off = 12; off < len; off += 23) {
			let values = unpack('!HIIB', payload, off + 12);

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res.links, {
				// ifname: ???,  /* FIXME */
				local_address: utils.ether_ntoa(payload, off),
				remote_address: utils.ether_ntoa(payload, off + 6),
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]],
				errors: values[1],
				packets: values[2],
				rssi: values[3]
			});
		}

		return res;
	},

	/** @param string al_address
	 *  @param string neighbor_al_address
	 *  @param Array<i1905lif|i1905rif> links */
	encode: (al_address, neighbor_al_address, links) => {
		let fmt = '!6s6s',
		    val = [ hexdec(al_address, ':'), hexdec(neighbor_al_address, ':') ];

		for (let i = 0; i < length(links); i += 2) {
			let i1905lif = links[i + 0],
			    i1905rif = links[i + 1],
			    metrics = i1905lif.getLinkMetrics(i1905rif.address);

			fmt += '6s6sHIIB';
			push(val,
				hexdec(i1905lif.address, ':'),
				hexdec(i1905rif.address, ':'),
				i1905lif.getMediaType(),
				metrics.rx_errors,
				metrics.rx_packets,
				metrics.rssi);
		}

		return pack(fmt, ...val);
	},
};
