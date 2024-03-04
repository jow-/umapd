import { pack, unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xc3,
	name: 'Profile-2 Steering Request',

	schema: {
		type: "object",
		properties: {
			bssid: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			request_mode: {
				type: "boolean"
			},
			btm_disassociation_imminent_bit: {
				type: "boolean"
			},
			btm_abridged_bit: {
				type: "boolean"
			},
			steering_opportunity_window: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 65535
			},
			btm_disassociation_timer: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 65535
			},
			sta_list: {
				type: "array",
				required: true,
				items: {
					type: "string",
					required: true,
					pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
				}
			},
			target_bssid_list: {
				type: "array",
				required: true,
				items: {
					type: "object",
					properties: {
						target_bssid: {
							type: "string",
							required: true,
							pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
						},
						target_bss_opclass: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						target_bss_channel: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						},
						reason_code: {
							type: "integer",
							required: true,
							minimum: 0,
							maximum: 255
						}
					}
				}
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 13)
			return null;

		let offset = 0;

		const bssid = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bitfield = ord(payload, offset++);
		const request_mode = ((bitfield & 0b10000000) == 0b10000000);
		const btm_disassociation_imminent_bit = ((bitfield & 0b01000000) == 0b01000000);
		const btm_abridged_bit = ((bitfield & 0b00100000) == 0b00100000);

		const steering_opportunity_window = unpack('!H', payload, offset);
		offset += 2;

		const btm_disassociation_timer = unpack('!H', payload, offset);
		offset += 2;

		const sta_list_count = ord(payload, offset++);

		const sta_list = [];
		for (let i = 0; i < sta_list_count; i++) {
			if (offset + 6 >= len)
				return null;

			const mac_address = utils.ether_ntoa(payload, offset);
			offset += 6;

			push(sta_list, mac_address);
		}

		const target_bssid_list_count = ord(payload, offset++);

		const target_bssid_list = [];
		for (let i = 0; i < target_bssid_list_count; i++) {
			if (offset + 9 >= len)
				return null;

			const target_bssid = utils.ether_ntoa(payload, offset);
			offset += 6;

			const target_bss_opclass = ord(payload, offset++);
			const target_bss_channel = ord(payload, offset++);
			const reason_code = ord(payload, offset++);

			push(target_bssid_list, {
				target_bssid,
				target_bss_opclass,
				target_bss_channel,
				reason_code,
			});
		}

		if (offset < len)
			return null;

		return {
			bssid,
			request_mode,
			btm_disassociation_imminent_bit,
			btm_abridged_bit,
			steering_opportunity_window,
			btm_disassociation_timer,
			sta_list,
			target_bssid_list,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		const bssid = utils.ether_aton(tlv.bssid);
		if (bssid == null)
			return null;

		if (type(tlv.request_mode) != "bool")
			return null;

		if (type(tlv.btm_disassociation_imminent_bit) != "bool")
			return null;

		if (type(tlv.btm_abridged_bit) != "bool")
			return null;

		if (type(tlv.steering_opportunity_window) != "int" || tlv.steering_opportunity_window < 0 || tlv.steering_opportunity_window > 0xffff)
			return null;

		if (type(tlv.btm_disassociation_timer) != "int" || tlv.btm_disassociation_timer < 0 || tlv.btm_disassociation_timer > 0xffff)
			return null;

		if (type(tlv.sta_list) != "array" || length(tlv.sta_list) > 0xff)
			return null;

		if (type(tlv.target_bssid_list) != "array" || length(tlv.target_bssid_list) > 0xff)
			return null;

		push(fmt, "6s");
		push(val, bssid);

		push(fmt, "B");
		push(val, 0
			| (tlv.request_mode << 7)
			| (tlv.btm_disassociation_imminent_bit << 6)
			| (tlv.btm_abridged_bit << 5)
		);

		push(fmt, "H");
		push(val, tlv.steering_opportunity_window);

		push(fmt, "H");
		push(val, tlv.btm_disassociation_timer);

		push(fmt, "B");
		push(val, length(tlv.sta_list));

		for (let mac_address in tlv.sta_list) {
			const _mac_address = utils.ether_aton(mac_address);
			if (_mac_address == null)
				return null;

			push(fmt, "6s");
			push(val, _mac_address);

		}

		push(fmt, "B");
		push(val, length(tlv.target_bssid_list));

		for (let item in tlv.target_bssid_list) {
			if (type(item) != "object")
				return null;

			const target_bssid = utils.ether_aton(item.target_bssid);
			if (target_bssid == null)
				return null;

			if (type(item.target_bss_opclass) != "int" || item.target_bss_opclass < 0 || item.target_bss_opclass > 0xff)
				return null;

			if (type(item.target_bss_channel) != "int" || item.target_bss_channel < 0 || item.target_bss_channel > 0xff)
				return null;

			if (type(item.reason_code) != "int" || item.reason_code < 0 || item.reason_code > 0xff)
				return null;

			push(fmt, "6s");
			push(val, target_bssid);

			push(fmt, "B");
			push(val, item.target_bss_opclass);

			push(fmt, "B");
			push(val, item.target_bss_channel);

			push(fmt, "B");
			push(val, item.reason_code);

		}

		return pack(join("", fmt), ...val);
	},

};
