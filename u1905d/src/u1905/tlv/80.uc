import defs from 'u1905.defs';

export default {
	type: 0x80,
	name: 'SupportedService',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let res = [];

		for (let off = 0; off < len; off++) {
			let supported_service = ord(payload, off);
			let supported_service_name = defs.SUPPORTED_SERVICES[supported_service];

			if (!supported_service_name)
				return null;

			push(res, {
				supported_service,
				supported_service_name
			});
		}

		return res;
	},

	/* Encoding not supported */
	encode: null,
};
