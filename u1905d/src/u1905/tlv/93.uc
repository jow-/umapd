import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x93,
	name: 'AP Metric Query',

	schema: {
		type: "array",
		required: true,
		items: {
			type: "string",
			required: true,
			pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const bssids_count = ord(payload, offset++);

		const bssids = [];
		for (let i = 0; i < bssids_count; i++) {
			if (offset + 6 >= len)
				return null;

			const bssid = utils.ether_ntoa(payload, offset);
			offset += 6;

			push(bssids, bssid);
		}

		if (offset < len)
			return null;

		return bssids;
	},

	encode: (bssids) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(bssids) != "array" || length(bssids) > 0xff)
			return null;

		push(fmt, "B");
		push(val, length(bssids));

		for (let bssid in bssids) {
			const _bssid = utils.ether_aton(bssid);
			if (_bssid == null)
				return null;

			push(fmt, "6s");
			push(val, _bssid);

		}

		return pack(join("", fmt), ...val);
	},

};
