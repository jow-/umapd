import { pack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0xbf,
	name: 'Association Status Notification',

	schema: {
		type: "array",
		required: true,
		items: {
			type: "object",
			properties: {
				bssid: {
					type: "string",
					required: true,
					pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
				},
				association_allowance_status: {
					type: "integer",
					required: true,
					enum: [ 0x00, 0x01 ]
				}
			}
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
			if (offset + 7 >= len)
				return null;

			const bssid = utils.ether_ntoa(payload, offset);
			offset += 6;

			const association_allowance_status = ord(payload, offset++);

			if (!exists(defs.ASSOCIATION_ALLOWANCE_STATUS, association_allowance_status))
				return null;

			push(bssids, {
				bssid,
				association_allowance_status,
				association_allowance_status_name: defs.ASSOCIATION_ALLOWANCE_STATUS[association_allowance_status],
			});
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

		for (let item in bssids) {
			if (type(item) != "object")
				return null;

			const bssid = utils.ether_aton(item.bssid);
			if (bssid == null)
				return null;

			if (!(item.association_allowance_status in [ 0x00, 0x01 ]))
				return null;

			push(fmt, "6s");
			push(val, bssid);

			push(fmt, "B");
			push(val, item.association_allowance_status);

		}

		return pack(join("", fmt), ...val);
	},

};
