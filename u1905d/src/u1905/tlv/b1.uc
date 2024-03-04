import { pack, unpack } from 'struct';

export default {
	type: 0xb1,
	name: 'CAC Status Report',

	schema: {
		type: "object",
		properties: {
			available_channels: {
				type: "array",
				required: true,
				items: {
					type: "object",
					properties: {
						opclass: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						channel: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						minutes: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 65535
						}
					}
				}
			},
			pairs: {
				type: "array",
				required: true,
				items: {
					type: "object",
					properties: {
						opclass: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						channel: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						duration: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 65535
						}
					}
				}
			},
			pairs2: {
				type: "array",
				required: true,
				items: {
					type: "object",
					properties: {
						opclass: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						channel: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						countdown: {
							type: "string",
							required: true,
							minLength: 3,
							maxLength: 3
						}
					}
				}
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 3)
			return null;

		let offset = 0;
		const available_channels_count = ord(payload, offset++);

		const available_channels = [];
		for (let i = 0; i < available_channels_count; i++) {
			if (offset + 4 >= len)
				return null;

			const opclass = ord(payload, offset++);
			const channel = ord(payload, offset++);

			const minutes = unpack('!H', payload, offset);
			offset += 2;

			push(available_channels, {
				opclass,
				channel,
				minutes,
			});
		}

		const pairs_count = ord(payload, offset++);

		const pairs = [];
		for (let i = 0; i < pairs_count; i++) {
			if (offset + 4 >= len)
				return null;

			const opclass = ord(payload, offset++);
			const channel = ord(payload, offset++);

			const duration = unpack('!H', payload, offset);
			offset += 2;

			push(pairs, {
				opclass,
				channel,
				duration,
			});
		}

		const pairs_count2 = ord(payload, offset++);

		const pairs2 = [];
		for (let i = 0; i < pairs_count2; i++) {
			if (offset + 5 >= len)
				return null;

			const opclass = ord(payload, offset++);
			const channel = ord(payload, offset++);

			const countdown = unpack('3s', payload, offset);
			offset += 3;

			push(pairs2, {
				opclass,
				channel,
				countdown,
			});
		}

		if (offset < len)
			return null;

		return {
			available_channels,
			pairs,
			pairs2,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.available_channels) != "array" || length(tlv.available_channels) > 0xff)
			return null;

		if (type(tlv.pairs) != "array" || length(tlv.pairs) > 0xff)
			return null;

		if (type(tlv.pairs2) != "array" || length(tlv.pairs2) > 0xff)
			return null;

		push(fmt, "B");
		push(val, length(tlv.available_channels));

		for (let item in tlv.available_channels) {
			if (type(item) != "object")
				return null;

			if (type(item.opclass) != "int" || item.opclass < 0 || item.opclass > 0xff)
				return null;

			if (type(item.channel) != "int" || item.channel < 0 || item.channel > 0xff)
				return null;

			if (type(item.minutes) != "int" || item.minutes < 0 || item.minutes > 0xffff)
				return null;

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "B");
			push(val, item.channel);

			push(fmt, "H");
			push(val, item.minutes);

		}

		push(fmt, "B");
		push(val, length(tlv.pairs));

		for (let item in tlv.pairs) {
			if (type(item) != "object")
				return null;

			if (type(item.opclass) != "int" || item.opclass < 0 || item.opclass > 0xff)
				return null;

			if (type(item.channel) != "int" || item.channel < 0 || item.channel > 0xff)
				return null;

			if (type(item.duration) != "int" || item.duration < 0 || item.duration > 0xffff)
				return null;

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "B");
			push(val, item.channel);

			push(fmt, "H");
			push(val, item.duration);

		}

		push(fmt, "B");
		push(val, length(tlv.pairs2));

		for (let item in tlv.pairs2) {
			if (type(item) != "object")
				return null;

			if (type(item.opclass) != "int" || item.opclass < 0 || item.opclass > 0xff)
				return null;

			if (type(item.channel) != "int" || item.channel < 0 || item.channel > 0xff)
				return null;

			if (type(item.countdown) != "string" || length(item.countdown) > 3)
				return null;

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "B");
			push(val, item.channel);

			push(fmt, "3s");
			push(val, item.countdown);

		}

		return pack(join("", fmt), ...val);
	},

};
