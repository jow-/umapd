import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x9e,
	name: 'Backhaul Steering Request',

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
			opclass: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			channel_number: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 14)
			return null;

		let offset = 0;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bssid = utils.ether_ntoa(payload, offset);
		offset += 6;

		const opclass = ord(payload, offset++);
		const channel_number = ord(payload, offset++);

		if (offset < len)
			return null;

		return {
			mac_address,
			bssid,
			opclass,
			channel_number,
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

		if (type(tlv.opclass) != "int" || tlv.opclass < 0 || tlv.opclass > 0xff)
			return null;

		if (type(tlv.channel_number) != "int" || tlv.channel_number < 0 || tlv.channel_number > 0xff)
			return null;

		push(fmt, "6s");
		push(val, mac_address);

		push(fmt, "6s");
		push(val, bssid);

		push(fmt, "B");
		push(val, tlv.opclass);

		push(fmt, "B");
		push(val, tlv.channel_number);

		return pack(join("", fmt), ...val);
	},

};
