import { pack, unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x94,
	name: 'AP Metrics',

	schema: {
		type: "object",
		properties: {
			bssid: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			channel_utilization: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			},
			sta_count: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 65535
			},
			esp_be: {
				type: "string",
				required: true,
				minLength: 3,
				maxLength: 3
			},
			esp_bk: {
				type: "string",
				minLength: 3,
				maxLength: 3
			},
			esp_vo: {
				type: "string",
				minLength: 3,
				maxLength: 3
			},
			esp_vi: {
				type: "string",
				minLength: 3,
				maxLength: 3
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

		const channel_utilization = ord(payload, offset++);

		const sta_count = unpack('!H', payload, offset);
		offset += 2;

		const bitfield = ord(payload, offset++);
		const include_esp_be = ((bitfield & 0b10000000) == 0b10000000);
		const include_esp_bk = ((bitfield & 0b01000000) == 0b01000000);
		const include_esp_vo = ((bitfield & 0b00100000) == 0b00100000);
		const include_esp_vi = ((bitfield & 0b00010000) == 0b00010000);

		if (include_esp_be != true)
			return null;

		const esp_be = unpack('3s', payload, offset);
		offset += 3;

		let esp_bk = null;
		if (include_esp_bk && offset + 3 <= len) {
			esp_bk = unpack('3s', payload, offset);
			offset += 3;
		}

		let esp_vo = null;
		if (include_esp_vo && offset + 3 <= len) {
			esp_vo = unpack('3s', payload, offset);
			offset += 3;
		}

		let esp_vi = null;
		if (include_esp_vi && offset + 3 <= len) {
			esp_vi = unpack('3s', payload, offset);
			offset += 3;
		}

		if (offset < len)
			return null;

		return {
			bssid,
			channel_utilization,
			sta_count,
			esp_be,
			esp_bk,
			esp_vo,
			esp_vi,
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

		if (type(tlv.channel_utilization) != "int" || tlv.channel_utilization < 0 || tlv.channel_utilization > 0xff)
			return null;

		if (type(tlv.sta_count) != "int" || tlv.sta_count < 0 || tlv.sta_count > 0xffff)
			return null;

		if (type(tlv.esp_be) != "string" || length(tlv.esp_be) > 3)
			return null;

		if (tlv.esp_bk != null && (type(tlv.esp_bk) != "string" || length(tlv.esp_bk) > 3))
			return null;

		if (tlv.esp_vo != null && (type(tlv.esp_vo) != "string" || length(tlv.esp_vo) > 3))
			return null;

		if (tlv.esp_vi != null && (type(tlv.esp_vi) != "string" || length(tlv.esp_vi) > 3))
			return null;

		push(fmt, "6s");
		push(val, bssid);

		push(fmt, "B");
		push(val, tlv.channel_utilization);

		push(fmt, "!H");
		push(val, tlv.sta_count);

		push(fmt, "B");
		push(val, 0b10000000
			| ((tlv.include_esp_bk != null) << 6)
			| ((tlv.include_esp_vo != null) << 5)
			| ((tlv.include_esp_vi != null) << 4)
		);

		push(fmt, "3s");
		push(val, tlv.esp_be);

		if (tlv.esp_bk != null) {
			push(fmt, "3s");
			push(val, tlv.esp_bk);
		}

		if (tlv.esp_vo != null) {
			push(fmt, "3s");
			push(val, tlv.esp_vo);
		}

		if (tlv.esp_vi != null) {
			push(fmt, "3s");
			push(val, tlv.esp_vi);
		}

		return pack(join("", fmt), ...val);
	},

};
