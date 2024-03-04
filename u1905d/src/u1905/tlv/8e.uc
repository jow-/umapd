import { pack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

export default {
	type: 0x8e,
	name: 'Channel Selection Response',

	schema: {
		type: "object",
		properties: {
			radio_unique_identifier: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			channel_selection_response_code: {
				type: "integer",
				required: true,
				enum: [ 0x00, 0x01, 0x02, 0x03 ]
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

		const channel_selection_response_code = ord(payload, offset++);

		if (!exists(defs.CHANNEL_SELECTION_RESPONSE_CODE, channel_selection_response_code))
			return null;

		if (offset < len)
			return null;

		return {
			radio_unique_identifier,
			channel_selection_response_code,
			channel_selection_response_code_name: defs.CHANNEL_SELECTION_RESPONSE_CODE[channel_selection_response_code],
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

		if (!(tlv.channel_selection_response_code in [ 0x00, 0x01, 0x02, 0x03 ]))
			return null;

		push(fmt, "6s");
		push(val, radio_unique_identifier);

		push(fmt, "B");
		push(val, tlv.channel_selection_response_code);

		return pack(join("", fmt), ...val);
	},

};
