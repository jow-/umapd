import { pack, unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x09,
	name: 'Transmitter link metric',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len <= 12 || ((len - 12) % 29))
			return null;

		let res = {
			al_address: utils.ether_ntoa(payload, 0),
			neighbor_al_address: utils.ether_ntoa(payload, 6),
			links: []
		};

		for (let off = 12; off < len; off += 29) {
			let values = unpack('!HBIIHHH', payload, off + 12);

			if (values[1] > 0x01)
				return null;

			if (!defs.MEDIA_TYPES[values[0]])
				return null;

			push(res.links, {
				// ifname: ???,  /* FIXME */
				local_address: utils.ether_ntoa(payload, off),
				remote_address: utils.ether_ntoa(payload, off + 6),
				media_type: values[0],
				media_type_name: defs.MEDIA_TYPES[values[0]],
				is_bridge: (values[1] == 0x01),
				errors: values[2],
				packets: values[3],
				throughput: values[4],
				availability: values[5],
				speed: values[6]
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

			fmt += '6s6sHBIIHHH';
			push(val,
				hexdec(i1905lif.address, ':'),
				hexdec(i1905rif.address, ':'),
				i1905lif.getMediaType(),
				i1905rif.isBridged() ? 0x01 : 0x00,
				metrics.tx_errors,
				metrics.tx_packets,
				metrics.throughput,
				metrics.availability,
				metrics.phyrate
			);
		}

		return pack(fmt, ...val);
	},
};
