import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x99,
	name: 'Beacon Metrics Query',

	schema: {
		type: "object",
		properties: {
			mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			opclass_field: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			channel_number_field: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			bssid_field: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			reporting_detail_value: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			ssid: {
				type: "string",
				required: true
			},
			ap_channel_reports: {
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
						channel_list: {
							type: "string",
							required: true
						}
					}
				}
			},
			element_list: {
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

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const opclass_field = ord(payload, offset++);
		const channel_number_field = ord(payload, offset++);

		const bssid_field = utils.ether_ntoa(payload, offset);
		offset += 6;

		const reporting_detail_value = ord(payload, offset++);
		const ssid_length = ord(payload, offset++);

		if (offset + ssid_length >= len)
			return null;

		const ssid = substr(payload, offset, ssid_length);
		offset += ssid_length;

		const ap_channel_reports_count = ord(payload, offset++);

		const ap_channel_reports = [];
		for (let i = 0; i < ap_channel_reports_count; i++) {
			if (offset + 1 >= len)
				return null;

			const ap_channel_report_length = ord(payload, offset++);
			const opclass = ord(payload, offset++);

			if (offset + ap_channel_report_length - 1 >= len)
				return null;

			const channel_list = substr(payload, offset, ap_channel_report_length - 1);
			offset += ap_channel_report_length - 1;

			push(ap_channel_reports, {
				ap_channel_report_length,
				opclass,
				channel_list,
			});
		}

		const element_ids_count = ord(payload, offset++);

		if (offset + element_ids_count >= len)
			return null;

		const element_list = substr(payload, offset, element_ids_count);
		offset += element_ids_count;

		if (offset < len)
			return null;

		return {
			mac_address,
			opclass_field,
			channel_number_field,
			bssid_field,
			reporting_detail_value,
			ssid_length,
			ssid,
			ap_channel_reports,
			element_ids_count,
			element_list,
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

		if (type(tlv.opclass_field) != "int" || tlv.opclass_field < 0 || tlv.opclass_field > 0xff)
			return null;

		if (type(tlv.channel_number_field) != "int" || tlv.channel_number_field < 0 || tlv.channel_number_field > 0xff)
			return null;

		const bssid_field = utils.ether_aton(tlv.bssid_field);
		if (bssid_field == null)
			return null;

		if (type(tlv.reporting_detail_value) != "int" || tlv.reporting_detail_value < 0 || tlv.reporting_detail_value > 0xff)
			return null;

		if (type(tlv.ssid) != "string" || length(tlv.ssid) > 0xff)
			return null;

		if (type(tlv.ap_channel_reports) != "array" || length(tlv.ap_channel_reports) > 0xff)
			return null;

		if (type(tlv.element_list) != "string" || length(tlv.element_list) > 0xff)
			return null;

		push(fmt, "6s");
		push(val, mac_address);

		push(fmt, "B");
		push(val, tlv.opclass_field);

		push(fmt, "B");
		push(val, tlv.channel_number_field);

		push(fmt, "6s");
		push(val, bssid_field);

		push(fmt, "B");
		push(val, tlv.reporting_detail_value);

		push(fmt, "B");
		push(val, length(tlv.ssid));

		push(fmt, "*");
		push(val, tlv.ssid);

		push(fmt, "B");
		push(val, length(tlv.ap_channel_reports));

		for (let item in tlv.ap_channel_reports) {
			if (type(item) != "object")
				return null;

			if (type(item.opclass) != "int" || item.opclass < 0 || item.opclass > 0xff)
				return null;

			if (type(item.channel_list) != "string" || length(item.channel_list) > 0xff - 18446744073709551615)
				return null;

			push(fmt, "B");
			push(val, length(item.channel_list) + 1);

			push(fmt, "B");
			push(val, item.opclass);

			push(fmt, "*");
			push(val, item.channel_list);

		}

		push(fmt, "B");
		push(val, length(tlv.element_list));

		push(fmt, "*");
		push(val, tlv.element_list);

		return pack(join("", fmt), ...val);
	},

};
