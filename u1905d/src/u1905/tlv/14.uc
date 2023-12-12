import { pack, unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x14,
	name: 'Generic Phy device information',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len <= 7)
			return null;

		let res = {
			al_address: utils.ether_ntoa(payload, 0),
			links: []
		};

		let num_ifaces = ord(payload, 6);

		for (let off = 7, i = 0; off < len && i < num_ifaces; off += 44, i++) {
			if (off + 44 > len)
				return null;

			let url_len = ord(payload, off + 42);
			let info_len = ord(payload, off + 43);

			if (off + 44 + url_len + info_len > len)
				return null;

			push(res.links, {
				local_address: utils.ether_ntoa(payload, off),
				oui: sprintf('%02x:%02x:%02x', ...unpack(payload, '!3B', off + 6)),
				variant_index: ord(payload, off + 9),
				variant_name: trim(substr(payload, off + 10, 32)),
				xml_description_url: substr(payload, off + 44, url_len),
				media_info: substr(payload, off + 44 + url_len, info_len)
			});
		}

		return res;
	},

	/** @param string al_address
	 *  @param ...ifnames ifnames */
	encode: (al_address, ...ifnames) => {
		if (length(ifnames))
			die('Generic phy description not implemented');

		return pack('!6sB',
			hexdec(al_address, ':'),
			length(ifnames));
	},
};
