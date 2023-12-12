import utils from 'u1905.utils';

export default {
	type: 0x02,
	name: 'MAC address',

	/** @param string payload */
	decode: (payload) => utils.ether_ntoa(payload),

	/** @param string mac */
	encode: (mac) => utils.ether_aton(mac),
};
