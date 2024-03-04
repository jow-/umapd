import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x92,
	name: 'Client Association Event',

	schema: {
		type: "object",
		properties: {
			mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			bssid: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			association_event: {
				type: "boolean"
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 13)
			return null;

		let offset = 0;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bssid = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bitfield = ord(payload, offset++);
		const association_event = ((bitfield & 0b10000000) == 0b10000000);

		if (offset < len)
			return null;

		return {
			mac_address,
			bssid,
			association_event,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		const mac_address = utils.ether_aton(tlv.mac_address);
		if (mac_address == null)
			return null;

		const bssid = utils.ether_aton(tlv.bssid);
		if (bssid == null)
			return null;

		if (type(tlv.association_event) != "bool")
			return null;

		push(fmt, "6s");
		push(val, mac_address);

		push(fmt, "6s");
		push(val, bssid);

		push(fmt, "B");
		push(val, 0
			| (tlv.association_event << 7)
		);

		return pack(join("", fmt), ...val);
	},

};
