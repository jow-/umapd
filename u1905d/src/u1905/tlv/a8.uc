import { pack } from 'struct';

export default {
	type: 0xa8,
	name: 'Timestamp',

	schema: {
		type: "string",
		required: true
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const timestamp_length = ord(payload, offset++);

		if (offset + timestamp_length >= len)
			return null;

		const timestamp = substr(payload, offset, timestamp_length);
		offset += timestamp_length;

		if (offset < len)
			return null;

		return {
			timestamp_length,
			timestamp,
		};
	},

	encode: (timestamp) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(timestamp) != "string" || length(timestamp) > 0xff)
			return null;

		push(fmt, "B");
		push(val, length(timestamp));

		push(fmt, "*");
		push(val, timestamp);

		return pack(join("", fmt), ...val);
	},

};
