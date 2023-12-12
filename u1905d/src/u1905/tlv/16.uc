export default {
	type: 0x16,
	name: 'Control URL',

	/** @param string payload */
	decode: (payload) => payload,

	/** @param string url */
	encode: (url) => url,
};
