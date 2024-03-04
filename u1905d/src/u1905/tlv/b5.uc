import { pack, unpack } from 'struct';

export default {
	type: 0xb5,
	name: 'Default 802.1Q Settings',

	schema: {
		type: "object",
		properties: {
			primary_vlan_id: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 65535
			},
			default_pcp: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 8
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 3)
			return null;

		let offset = 0;

		const primary_vlan_id = unpack('!H', payload, offset);
		offset += 2;

		const bitfield = ord(payload, offset++);
		const default_pcp = (bitfield >> 5) & 0b111;

		if (offset < len)
			return null;

		return {
			primary_vlan_id,
			default_pcp,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.primary_vlan_id) != "int" || tlv.primary_vlan_id < 0 || tlv.primary_vlan_id > 0xffff)
			return null;

		if (type(tlv.default_pcp) != "int" || tlv.default_pcp < 0 || tlv.default_pcp > 0b111)
			return null;

		push(fmt, "H");
		push(val, tlv.primary_vlan_id);

		push(fmt, "B");
		push(val, 0
			| ((tlv.default_pcp & 0b111) << 5)
		);

		return pack(join("", fmt), ...val);
	},

};
