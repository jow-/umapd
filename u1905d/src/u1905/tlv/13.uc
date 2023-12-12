import utils from 'u1905.utils';

export default {
	type: 0x13,
	name: 'Push_Button_Join notification',

	/** @param string payload */
	decode: (payload) => {
		if (length(payload) != 20)
			return null;

		return {
			al_address: utils.ether_ntoa(payload, 0),
			mid: ord(payload, 6) * 256 + ord(payload, 7),
			local_address: utils.ether_ntoa(payload, 8),
			remote_address: utils.ether_ntoa(payload, 14)
		};
	},

	/* Encoding unsupported */
	encode: null,
};
