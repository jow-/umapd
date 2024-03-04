import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xc0,
	name: 'Source Info',

	schema: {
		type: "string",
		required: true,
		pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 6)
			return null;

		let offset = 0;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		if (offset < len)
			return null;

		return mac_address;
	},

	encode: (mac_address) => {
		const fmt = [ "!" ];
		const val = [];

		const _mac_address = utils.ether_aton(mac_address);
		if (_mac_address == null)
			return null;

		push(fmt, "6s");
		push(val, _mac_address);

		return pack(join("", fmt), ...val);
	},

};
