import { pack, unpack } from 'struct';
import utils from 'u1905.utils';

export default {
	type: 0xa2,
	name: 'Associated STA Traffic Stats',

	schema: {
		type: "object",
		properties: {
			mac_address: {
				type: "string",
				required: true,
				pattern: "^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$"
			},
			bytes_sent: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 4294967295
			},
			bytes_received: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 4294967295
			},
			packets_sent: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 4294967295
			},
			packets_received: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 4294967295
			},
			tx_packets_errors: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 4294967295
			},
			rx_packets_errors: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 4294967295
			},
			retransmission_count: {
				type: "integer",
				required: true,
				minimum: 0,
				maximum: 4294967295
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 34)
			return null;

		let offset = 0;

		const mac_address = utils.ether_ntoa(payload, offset);
		offset += 6;

		const bytes_sent = unpack('!L', payload, offset);
		offset += 4;

		const bytes_received = unpack('!L', payload, offset);
		offset += 4;

		const packets_sent = unpack('!L', payload, offset);
		offset += 4;

		const packets_received = unpack('!L', payload, offset);
		offset += 4;

		const tx_packets_errors = unpack('!L', payload, offset);
		offset += 4;

		const rx_packets_errors = unpack('!L', payload, offset);
		offset += 4;

		const retransmission_count = unpack('!L', payload, offset);
		offset += 4;

		if (offset < len)
			return null;

		return {
			mac_address,
			bytes_sent,
			bytes_received,
			packets_sent,
			packets_received,
			tx_packets_errors,
			rx_packets_errors,
			retransmission_count,
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

		if (type(tlv.bytes_sent) != "int" || tlv.bytes_sent < 0 || tlv.bytes_sent > 0xffffffff)
			return null;

		if (type(tlv.bytes_received) != "int" || tlv.bytes_received < 0 || tlv.bytes_received > 0xffffffff)
			return null;

		if (type(tlv.packets_sent) != "int" || tlv.packets_sent < 0 || tlv.packets_sent > 0xffffffff)
			return null;

		if (type(tlv.packets_received) != "int" || tlv.packets_received < 0 || tlv.packets_received > 0xffffffff)
			return null;

		if (type(tlv.tx_packets_errors) != "int" || tlv.tx_packets_errors < 0 || tlv.tx_packets_errors > 0xffffffff)
			return null;

		if (type(tlv.rx_packets_errors) != "int" || tlv.rx_packets_errors < 0 || tlv.rx_packets_errors > 0xffffffff)
			return null;

		if (type(tlv.retransmission_count) != "int" || tlv.retransmission_count < 0 || tlv.retransmission_count > 0xffffffff)
			return null;

		push(fmt, "6s");
		push(val, mac_address);

		push(fmt, "L");
		push(val, tlv.bytes_sent);

		push(fmt, "L");
		push(val, tlv.bytes_received);

		push(fmt, "L");
		push(val, tlv.packets_sent);

		push(fmt, "L");
		push(val, tlv.packets_received);

		push(fmt, "L");
		push(val, tlv.tx_packets_errors);

		push(fmt, "L");
		push(val, tlv.rx_packets_errors);

		push(fmt, "L");
		push(val, tlv.retransmission_count);

		return pack(join("", fmt), ...val);
	},

};
