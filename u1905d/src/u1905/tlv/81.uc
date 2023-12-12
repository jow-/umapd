import defs from 'u1905.defs';

export default {
	type: 0x81,
	name: 'SearchedService',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 1)
			return null;

		let res = [];

		for (let off = 0; off < len; off++) {
			let searched_service = ord(payload, off);
			let searched_service_name = defs.SEARCHED_SERVICES[searched_service];

			if (!searched_service_name)
				return null;

			push(res, {
				searched_service,
				searched_service_name
			});
		}

		return res;
	},

	/* Encoding not supported */
	encode: null,
};
