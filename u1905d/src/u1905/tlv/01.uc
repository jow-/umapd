import utils from 'u1905.utils';

export default {
	type: 0x01,
	name: 'AL MAC address',

	/** @param string payload */
	decode: (payload) => utils.ether_ntoa(payload),

	/** @param string mac */
	encode: (mac) => utils.ether_aton(mac),
};
