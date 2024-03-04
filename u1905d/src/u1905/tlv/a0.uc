import { pack } from 'struct';

export default {
	type: 0xa0,
	name: 'Higher Layer Data',

	schema: {
		type: "object",
		properties: {
			higher_layer_protocol: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			higher_layer_protocol_payload: {
				type: "string",
				required: true
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const higher_layer_protocol = ord(payload, offset++);
		const higher_layer_protocol_payload = unpack('*', payload, offset);

		return {
			higher_layer_protocol,
			higher_layer_protocol_payload,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.higher_layer_protocol) != "int" || tlv.higher_layer_protocol < 0 || tlv.higher_layer_protocol > 0xff)
			return null;

		if (type(tlv.higher_layer_protocol_payload) != "string")
			return null;

		push(fmt, "B");
		push(val, tlv.higher_layer_protocol);

		push(fmt, "*");
		push(val, tlv.higher_layer_protocol_payload);

		return pack(join("", fmt), ...val);
	},

};
