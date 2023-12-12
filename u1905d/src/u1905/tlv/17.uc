import { pack, unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x17,
	name: 'IPv4',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_ifaces = ord(payload, 0);
		let res = [];

		for (let off = 1, i = 0; off < len && i < num_ifaces; i++) {
			if (off + 7 > len)
				return null;

			let address = utils.ether_ntoa(payload, off);
			let num_addrs = ord(payload, off + 6);

			off += 7;

			if (off + num_addrs * 9 > len)
				return null;

			let entry = {
				address,
				ipaddrs: []
			};

			for (let j = 0; j < num_addrs; off += 9, j++) {
				push(entry.ipaddrs, {
					type: ord(payload, off),
					type_name: defs.IPV4ADDR_TYPES[ord(payload, off)] ?? 'Reserved',
					ipaddr: arrtoip(unpack('!4B', payload, off + 1)),
					dhcpaddr: arrtoip(unpack('!4B', payload, off + 5))
				});
			}

			push(res, entry);
		}

		return res;
	},

	/** @param i1905lif[] links
	 *  @param object ifstatus */
	encode: (links, ifstatus) => {
		assert(length(links) <= 255, 'Too many interfaces for TLV');

		let fmt = '!B';
		let val = [ 0 ];

		for (let i1905lif in links) {
			let ipaddrs = i1905lif.getIPAddrs(ifstatus);

			if (!length(ipaddrs))
				continue;

			val[0]++;
			fmt += '6sB';
			push(val, hexdec(i1905lif.address, ':'), length(ipaddrs));

			for (let i, addr in ipaddrs) {
				if (i >= 16)
					break;

				fmt += 'B4B4B';
				push(val, addr[2], ...iptoarr(addr[0]), ...iptoarr(addr[3]));
			}
		}

		return pack(fmt, ...val);
	},
};
