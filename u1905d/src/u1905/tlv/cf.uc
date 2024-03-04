import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xcf,
	name: 'DPP Bootstrapping URI Notification',

	schema: {
		type: "object",
		properties: {
			radio_unique_identifier: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			bssid: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			b_sta_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			dpp_uri: {
				type: "string",
				required: true
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 18)
			return null;

		let offset = 0;

		const radio_unique_identifier = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bssid = utils.ether_ntoa(payload, offset);
		offset += 6;

		const b_sta_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const dpp_uri = unpack('*', payload, offset);

		return {
			radio_unique_identifier,
			bssid,
			b_sta_address,
			dpp_uri,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		const radio_unique_identifier = utils.ether_aton(tlv.radio_unique_identifier);
		if (radio_unique_identifier == null)
			return null;

		const bssid = utils.ether_aton(tlv.bssid);
		if (bssid == null)
			return null;

		const b_sta_address = utils.ether_aton(tlv.b_sta_address);
		if (b_sta_address == null)
			return null;

		if (type(tlv.dpp_uri) != "string")
			return null;

		push(fmt, "6s");
		push(val, radio_unique_identifier);

		push(fmt, "6s");
		push(val, bssid);

		push(fmt, "6s");
		push(val, b_sta_address);

		push(fmt, "*");
		push(val, tlv.dpp_uri);

		return pack(join("", fmt), ...val);
	},

};
