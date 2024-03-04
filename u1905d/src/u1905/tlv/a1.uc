import { pack } from 'struct';

export default {
	type: 0xa1,
	name: 'AP Capability',

	schema: {
		type: "object",
		properties: {
			onchannel_unassoc_sta_link_metrics: {
				type: "boolean"
			},
			offchannel_unassoc_sta_link_metrics: {
				type: "boolean"
			},
			agent_initiated_rcpi_based_steering: {
				type: "boolean"
			}
		}
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const bitfield = ord(payload, offset++);
		const onchannel_unassoc_sta_link_metrics = ((bitfield & 0b10000000) == 0b10000000);
		const offchannel_unassoc_sta_link_metrics = ((bitfield & 0b01000000) == 0b01000000);
		const agent_initiated_rcpi_based_steering = ((bitfield & 0b00100000) == 0b00100000);

		if (offset < len)
			return null;

		return {
			onchannel_unassoc_sta_link_metrics,
			offchannel_unassoc_sta_link_metrics,
			agent_initiated_rcpi_based_steering,
		};
	},

	encode: (tlv) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(tlv) != "object")
			return null;

		if (type(tlv.onchannel_unassoc_sta_link_metrics) != "bool")
			return null;

		if (type(tlv.offchannel_unassoc_sta_link_metrics) != "bool")
			return null;

		if (type(tlv.agent_initiated_rcpi_based_steering) != "bool")
			return null;

		push(fmt, "B");
		push(val, 0
			| (tlv.onchannel_unassoc_sta_link_metrics << 7)
			| (tlv.offchannel_unassoc_sta_link_metrics << 6)
			| (tlv.agent_initiated_rcpi_based_steering << 5)
		);

		return pack(join("", fmt), ...val);
	},

};
