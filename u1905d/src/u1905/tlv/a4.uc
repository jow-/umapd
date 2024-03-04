import { pack } from 'struct';

export default {
	type: 0xa4,
	name: 'Channel Scan Reporting Policy',

	schema: {
		type: "boolean"
	},

	decode: (payload) => {
		const len = length(payload);

		if (len < 1)
			return null;

		let offset = 0;
		const bitfield = ord(payload, offset++);
		const report_independent_channel_scans = ((bitfield & 0b10000000) == 0b10000000);

		if (offset < len)
			return null;

		return report_independent_channel_scans;
	},

	encode: (report_independent_channel_scans) => {
		const fmt = [ "!" ];
		const val = [];

		if (type(report_independent_channel_scans) != "bool")
			return null;

		push(fmt, "B");
		push(val, 0
			| (report_independent_channel_scans << 7)
		);

		return pack(join("", fmt), ...val);
	},

};
