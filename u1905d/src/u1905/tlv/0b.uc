export default {
	type: 0x0b,
	name: 'Vendor specific',

	/** @param string payload */
	decode: (payload) => payload,

	/** @param string data */
	encode: (data) => data,
};
