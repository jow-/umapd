import { pack, unpack } from 'struct';

export default {
	type: 0xde,
	name: 'Trigger Channel Switch Announcement',

	schema: {
		type: "object",
		properties: {
			tlv_sub_type: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 65535
			},
			csa_channel: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			op_class: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 4)
			return null;

		let offset = 0;

		const tlv_sub_type = unpack('!H', payload, offset);
		offset += 2;

		const csa_channel = ord(payload, offset++);
		const op_class = ord(payload, offset++);

		if (offset < len)
			return null;

		return {
			tlv_sub_type,
			csa_channel,
			op_class,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.tlv_sub_type) != "int" || tlv.tlv_sub_type < 0 || tlv.tlv_sub_type > 0xffff)
			return null;

		if (type(tlv.csa_channel) != "int" || tlv.csa_channel < 0 || tlv.csa_channel > 0xff)
			return null;

		if (type(tlv.op_class) != "int" || tlv.op_class < 0 || tlv.op_class > 0xff)
			return null;

		push(fmt, "!H");
		push(val, tlv.tlv_sub_type);

		push(fmt, "B");
		push(val, tlv.csa_channel);

		push(fmt, "B");
		push(val, tlv.op_class);

		return pack(join("", fmt), ...val);
	},

};
