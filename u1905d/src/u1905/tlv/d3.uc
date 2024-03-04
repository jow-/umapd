import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xd3,
	name: 'DPP Chirp Value',

	schema: {
		type: "object",
		properties: {
			enrollee_mac_address_present: {
				type: "boolean"
			},
			hash_validity: {
				type: "boolean"
			},
			destination_sta_mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			hash_value: {
				type: "string",
				required: true
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 8)
			return null;

		let offset = 0;
		const bitfield = ord(payload, offset++);
		const enrollee_mac_address_present = ((bitfield & 0b10000000) == 0b10000000);
		const hash_validity = ((bitfield & 0b01000000) == 0b01000000);

		const destination_sta_mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const hash_length = ord(payload, offset++);

		if (offset + hash_length >= len)
			return null;

		const hash_value = substr(payload, offset, hash_length);
		offset += hash_length;

		if (offset < len)
			return null;

		return {
			enrollee_mac_address_present,
			hash_validity,
			destination_sta_mac_address,
			hash_length,
			hash_value,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.enrollee_mac_address_present) != "bool")
			return null;

		if (type(tlv.hash_validity) != "bool")
			return null;

		const destination_sta_mac_address = utils.ether_aton(tlv.destination_sta_mac_address);
		if (destination_sta_mac_address == null)
			return null;

		if (type(tlv.hash_value) != "string" || length(tlv.hash_value) > 0xff)
			return null;

		push(fmt, "B");
		push(val, 0
			| (tlv.enrollee_mac_address_present << 7)
			| (tlv.hash_validity << 6)
		);

		push(fmt, "6s");
		push(val, destination_sta_mac_address);

		push(fmt, "B");
		push(val, length(tlv.hash_value));

		push(fmt, "*");
		push(val, tlv.hash_value);

		return pack(join("", fmt), ...val);
	},

};
