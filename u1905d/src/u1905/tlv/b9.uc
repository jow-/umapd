import { pack, unpack } from 'struct';

export default {
	type: 0xb9,
	name: 'Service Prioritization Rule',

	schema: {
		type: "object",
		properties: {
			rule_id: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 4294967295
			},
			add_remove: {
				type: "boolean"
			},
			precedence: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			output: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			always_match: {
				type: "boolean"
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 8)
			return null;

		let offset = 0;

		const rule_id = unpack('!L', payload, offset);
		offset += 4;

		const bitfield = ord(payload, offset++);
		const add_remove = ((bitfield & 0b10000000) == 0b10000000);

		const precedence = ord(payload, offset++);
		const output = ord(payload, offset++);
		const bitfield2 = ord(payload, offset++);
		const always_match = ((bitfield2 & 0b10000000) == 0b10000000);

		if (offset < len)
			return null;

		return {
			rule_id,
			add_remove,
			precedence,
			output,
			always_match,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.rule_id) != "int" || tlv.rule_id < 0 || tlv.rule_id > 0xffffffff)
			return null;

		if (type(tlv.add_remove) != "bool")
			return null;

		if (type(tlv.precedence) != "int" || tlv.precedence < 0 || tlv.precedence > 0xff)
			return null;

		if (type(tlv.output) != "int" || tlv.output < 0 || tlv.output > 0xff)
			return null;

		if (type(tlv.always_match) != "bool")
			return null;

		push(fmt, "L");
		push(val, tlv.rule_id);

		push(fmt, "B");
		push(val, 0
			| (tlv.add_remove << 7)
		);

		push(fmt, "B");
		push(val, tlv.precedence);

		push(fmt, "B");
		push(val, tlv.output);

		push(fmt, "B");
		push(val, 0
			| (tlv.always_match << 7)
		);

		return pack(join("", fmt), ...val);
	},

};
