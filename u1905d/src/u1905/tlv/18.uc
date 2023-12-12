import { pack, unpack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x18,
	name: 'IPv6',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let num_ifaces = ord(payload, 0);
		let res;

		for (let off = 1, i = 0; off < len && i < num_ifaces; i++) {
			if (off + 23 > len)
				return null;

			let address = utils.ether_ntoa(payload, off);
			let ip6ll = arrtoip(unpack('!16B', payload, off + 6));
			let num_addrs = ord(payload, off + 22);

			off += 23;

			if (off + num_addrs * 33 > len)
				return null;

			let entry = {
				address,
				ip6ll,
				ip6addrs: []
			};

			for (let j = 0; j < num_addrs; off += 33, j++) {
				push(entry.ip6addrs, {
					type: ord(payload, off),
					type_name: defs.IPV6ADDR_TYPES[ord(payload, off)] ?? 'Reserved',
					ip6addr: arrtoip(unpack('!16B', payload, off + 1)),
					originaddr: arrtoip(unpack('!16B', payload, off + 17))
				});
			}

			push(res ??= [], entry);
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
			let ip6addrs = i1905lif.getIP6Addrs(ifstatus);

			if (!length(ip6addrs))
				continue;

			val[0]++;
			fmt += '6s16BB';
			push(val, hexdec(i1905lif.address, ':'), ...iptoarr(ip6addrs[0][0]), length(ip6addrs) - 1);

			for (let i, addr in ip6addrs) {
				if (i == 0)
					continue;

				if (i >= 17)
					break;

				fmt += 'B16B16B';
				push(val, addr[2], ...iptoarr(addr[0]), ...iptoarr(addr[3] ?? '::'));
			}
		}

		return pack(fmt, ...val);
	},
};
