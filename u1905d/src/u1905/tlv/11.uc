export default {
	type: 0x11,
	name: 'WSC',

	/** @param string payload */
	decode: (payload) => payload,

	/* Encoding unsupported */
	encode: null,
};
