import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x9a,
	name: 'Beacon Metrics Response',

	schema: {
		type: "object",
		properties: {
			mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			measurement_report_elements: {
				type: "array",
				required: true,
				items: {
					type: "string",
					required: true
				}
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 8)
			return null;

		let offset = 0;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const reserved = ord(payload, offset++);
		const measurement_report_elements_count = ord(payload, offset++);

		const measurement_report_elements = [];
		for (let i = 0; i < measurement_report_elements_count; i++) {
		}

		if (offset < len)
			return null;

		return {
			mac_address,
			measurement_report_elements,
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

		if (type(tlv.measurement_report_elements) != "array" || length(tlv.measurement_report_elements) > 0xff)
			return null;

		push(fmt, "6s");
		push(val, mac_address);

		push(fmt, "B");
		push(val, length(tlv.measurement_report_elements));

		for (let measurement_report_element in tlv.measurement_report_elements) {
			if (type(measurement_report_element) != "string")
				return null;

			push(fmt, "*");
			push(val, measurement_report_element);

		}

		return pack(join("", fmt), ...val);
	},

};
