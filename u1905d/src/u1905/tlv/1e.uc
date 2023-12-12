import { pack, unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x1e,
	name: 'L2 neighbor device',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_ifaces = ord(payload, 0);
		let res = [];

		for (let i = 0, off = 1; i < num_ifaces && off < len; i++) {
			if (off + 8 > len)
				return null;

			let num_neigh = unpack('!H', payload, off + 6)[0];

			push(res, {
				local_address: utils.ether_ntoa(payload, off),
				neighbor_devices: []
			});

			off += 8;

			for (let j = 0; j < num_neigh; j++) {
				if (off + 8 > len)
					return null;

				let num_addrs = unpack('!H', payload, off + 6)[0];

				push(res[-1].neighbor_devices, {
					remote_address: utils.ether_ntoa(payload, off),
					behind_addresses: []
				});

				off += 8;

				if (off + num_addrs * 6 > len)
					return null;

				for (let k = 0; k < num_addrs; k++, off += 6)
					push(res[-1].neighbor_devices[-1].behind_addresses, utils.ether_ntoa(payload, off));
			}
		}

		return res;
	},

	/** @param string local_address
	 *  @param string[] remote_addresses
	 *  @param i1905dev[] local_devices */
	encode: (local_address, remote_addresses, local_devices) => {
		let fmt = '!B';
		let val = [ 1 ];

		fmt += '6sH';
		push(val, hexdec(local_address, ':'), 0);

		for (let i, mac in remote_addresses) {
			if (i > 255)
				break;

			let off = length(val);

			fmt += '6sH';
			push(val, hexdec(mac, ':'), 0);

			for (let i1905dev in local_devices) {
				let i1905rif = i1905dev.lookupInterface(mac);

				if (!i1905rif)
					continue;

				let l2 = i1905dev.getTLVs(defs.TLV_L2_NEIGHBOR_DEVICE);

				if (length(l2)) {
					for (let tlv in l2) {
						for (let dev in tlv.decode()) {
							if (dev.local_address == mac)
								continue;

							for (let ndev in dev.neighbor_devices) {
								fmt += '6s';
								push(val, hexdec(ndev.remote_address, ':'));

								val[off + 1]++;
							}
						}
					}
				}
				else {
					let others = i1905dev.getTLVs(defs.TLV_NON1905_NEIGHBOR_DEVICES);
					let metrics = i1905dev.getTLVs(defs.TLV_LINK_METRIC_RX);

					for (let tlv in others) {
						let remote_addresses = tlv.decode();

						if (!remote_addresses || remote_addresses[0] == mac)
							continue;

						for (let j = 1; j < length(remote_addresses); j++) {
							fmt += '6s';
							push(val, hexdec(remote_addresses[j], ':'));

							val[off + 1]++;
						}
					}

					for (let tlv in metrics) {
						for (let link in tlv.decode()?.links) {
							if (link.local_address == mac)
								continue;

							fmt += '6s';
							push(val, hexdec(link.remote_address, ':'));

							val[off + 1]++;
						}
					}
				}
			}

			val[2]++;
		}

		return pack(fmt, ...val);
	},
};
