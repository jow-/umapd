import { pack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0x8d,
	name: 'Transmit Power Limit',

	schema: {
		type: "object",
		properties: {
			radio_unique_identifier: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			transmit_power_limit_eirp: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 255
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 7)
			return null;

		let offset = 0;

		const radio_unique_identifier = utils.ether_ntoa(payload, offset);
		offset += 6;

		const transmit_power_limit_eirp = ord(payload, offset++);

		if (offset < len)
			return null;

		return {
			radio_unique_identifier,
			transmit_power_limit_eirp,
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

		if (type(tlv.transmit_power_limit_eirp) != "int" || tlv.transmit_power_limit_eirp < 0 || tlv.transmit_power_limit_eirp > 0xff)
			return null;

		push(fmt, "6s");
		push(val, radio_unique_identifier);

		push(fmt, "B");
		push(val, tlv.transmit_power_limit_eirp);

		return pack(join("", fmt), ...val);
	},

};
