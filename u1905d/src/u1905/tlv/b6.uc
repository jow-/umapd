import { pack, unpack } from 'struct';

export default {
	type: 0xb6,
	name: 'Traffic Separation Policy',

	schema: {
		type: "array",
		required: true,
		items: {
			type: "object",
			properties: {
				ssid_name: {
					type: "string",
					required: true
				},
				vlan_id: {
					type: "integer",
					required: true,
					minimum: 0,
					maximum: 65535
				}
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const ssids_count = ord(payload, offset++);

		const ssids = [];
		for (let i = 0; i < ssids_count; i++) {
			if (offset + 3 >= len)
				return null;

			const ssid_name_length = ord(payload, offset++);

			if (offset + ssid_name_length >= len)
				return null;

			const ssid_name = substr(payload, offset, ssid_name_length);
			offset += ssid_name_length;

			const vlan_id = unpack('!H', payload, offset);
			offset += 2;

			push(ssids, {
				ssid_name_length,
				ssid_name,
				vlan_id,
			});
		}

		if (offset < len)
			return null;

		return ssids;
	},

	encode: (ssids) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(ssids) != "array" || length(ssids) > 0xff)
			return null;

		push(fmt, "B");
		push(val, length(ssids));

		for (let item in ssids) {
			if (type(item) != "object")
				return null;

			if (type(item.ssid_name) != "string" || length(item.ssid_name) > 0xff)
				return null;

			if (type(item.vlan_id) != "int" || item.vlan_id < 0 || item.vlan_id > 0xffff)
				return null;

			push(fmt, "B");
			push(val, length(item.ssid_name));

			push(fmt, "*");
			push(val, item.ssid_name);

			push(fmt, "!H");
			push(val, item.vlan_id);

		}

		return pack(join("", fmt), ...val);
	},

};
