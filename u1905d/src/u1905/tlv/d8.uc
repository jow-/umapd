import { pack, unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xd8,
	name: 'Spatial Reuse Request',

	schema: {
		type: "object",
		properties: {
			radio_unique_identifier: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			bss_color: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 64
			},
			hesiga_spatial_reuse_value15_allowed: {
				type: "boolean"
			},
			srg_information_valid: {
				type: "boolean"
			},
			non_srg_offset_valid: {
				type: "boolean"
			},
			psr_disallowed: {
				type: "boolean"
			},
			non_srg_obsspd_max_offset: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			srg_obsspd_min_offset: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			srg_obsspd_max_offset: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			srg_bss_color_bitmap: {
				type: "integer",
				required: true,
				minimum: 0
			},
			srg_partial_bssid_bitmap: {
				type: "integer",
				required: true,
				minimum: 0
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 29)
			return null;

		let offset = 0;

		const radio_unique_identifier = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bitfield = ord(payload, offset++);
		const bss_color = bitfield & 0b111111;

		const bitfield2 = ord(payload, offset++);
		const hesiga_spatial_reuse_value15_allowed = ((bitfield2 & 0b00010000) == 0b00010000);
		const srg_information_valid = ((bitfield2 & 0b00001000) == 0b00001000);
		const non_srg_offset_valid = ((bitfield2 & 0b00000100) == 0b00000100);
		const psr_disallowed = ((bitfield2 & 0b00000001) == 0b00000001);

		const non_srg_obsspd_max_offset = ord(payload, offset++);
		const srg_obsspd_min_offset = ord(payload, offset++);
		const srg_obsspd_max_offset = ord(payload, offset++);

		const srg_bss_color_bitmap = unpack('!Q', payload, offset);
		offset += 8;

		const srg_partial_bssid_bitmap = unpack('!Q', payload, offset);
		offset += 8;

		const reserved4 = unpack('!H', payload, offset);
		offset += 2;

		if (offset < len)
			return null;

		return {
			radio_unique_identifier,
			bss_color,
			hesiga_spatial_reuse_value15_allowed,
			srg_information_valid,
			non_srg_offset_valid,
			psr_disallowed,
			non_srg_obsspd_max_offset,
			srg_obsspd_min_offset,
			srg_obsspd_max_offset,
			srg_bss_color_bitmap,
			srg_partial_bssid_bitmap,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		const radio_unique_identifier = utils.ether_aton(tlv.radio_unique_identifier);
		if (radio_unique_identifier == null)
			return null;

		if (type(tlv.bss_color) != "int" || tlv.bss_color < 0 || tlv.bss_color > 0b111111)
			return null;

		if (type(tlv.hesiga_spatial_reuse_value15_allowed) != "bool")
			return null;

		if (type(tlv.srg_information_valid) != "bool")
			return null;

		if (type(tlv.non_srg_offset_valid) != "bool")
			return null;

		if (type(tlv.psr_disallowed) != "bool")
			return null;

		if (type(tlv.non_srg_obsspd_max_offset) != "int" || tlv.non_srg_obsspd_max_offset < 0 || tlv.non_srg_obsspd_max_offset > 0xff)
			return null;

		if (type(tlv.srg_obsspd_min_offset) != "int" || tlv.srg_obsspd_min_offset < 0 || tlv.srg_obsspd_min_offset > 0xff)
			return null;

		if (type(tlv.srg_obsspd_max_offset) != "int" || tlv.srg_obsspd_max_offset < 0 || tlv.srg_obsspd_max_offset > 0xff)
			return null;

		if (type(tlv.srg_bss_color_bitmap) != "int" || tlv.srg_bss_color_bitmap < 0 || tlv.srg_bss_color_bitmap > 0xffffffffffffffff)
			return null;

		if (type(tlv.srg_partial_bssid_bitmap) != "int" || tlv.srg_partial_bssid_bitmap < 0 || tlv.srg_partial_bssid_bitmap > 0xffffffffffffffff)
			return null;

		push(fmt, "6s");
		push(val, radio_unique_identifier);

		push(fmt, "B");
		push(val, 0
			| ((tlv.bss_color & 0b111111) << 0)
		);

		push(fmt, "B");
		push(val, 0
			| (tlv.hesiga_spatial_reuse_value15_allowed << 4)
			| (tlv.srg_information_valid << 3)
			| (tlv.non_srg_offset_valid << 2)
			| (tlv.psr_disallowed << 0)
		);

		push(fmt, "B");
		push(val, tlv.non_srg_obsspd_max_offset);

		push(fmt, "B");
		push(val, tlv.srg_obsspd_min_offset);

		push(fmt, "B");
		push(val, tlv.srg_obsspd_max_offset);

		push(fmt, "Q");
		push(val, tlv.srg_bss_color_bitmap);

		push(fmt, "Q");
		push(val, tlv.srg_partial_bssid_bitmap);

		return pack(join("", fmt), ...val);
	},

};
