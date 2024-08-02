import defs from 'u1905.defs';

// -----------------------------------------------------------------------------
// TLV ENCODER ROUTINES
// -----------------------------------------------------------------------------

export const encoder = [];

// 0x00 - End of message
// IEEE1905.1-2013
encoder[0x00] = (buf) => buf,

// 0x01 - 1905.1 AL MAC address
// IEEE1905.1-2013
encoder[0x01] = (buf, al_mac_address) => {
	const _al_mac_address = hexdec(match(al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (_al_mac_address == null)
		return null;

	buf.put('6s', _al_mac_address);

	return buf;
};

// 0x02 - MAC address
// IEEE1905.1-2013
encoder[0x02] = (buf, if_mac_address) => {
	const _if_mac_address = hexdec(match(if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (_if_mac_address == null)
		return null;

	buf.put('6s', _if_mac_address);

	return buf;
};

// 0x03 - 1905.1 device information
// IEEE1905.1-2013
encoder[0x03] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const al_mac_address = hexdec(match(tlv.al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (al_mac_address == null)
		return null;

	if (type(tlv.local_interfaces) != "array" || length(tlv.local_interfaces) > 0xff)
		return null;

	buf.put('6s', al_mac_address);
	buf.put('B', length(tlv.local_interfaces));

	for (let item in tlv.local_interfaces) {
		if (type(item) != "object")
			return null;

		const local_if_mac_address = hexdec(match(item.local_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (local_if_mac_address == null)
			return null;

		if (!(item.media_type in [ 0x0000, 0x0001, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0200, 0x0201, 0x0300, 0xffff ]))
			return null;

		if (type(item.media_specific_information) != "string" || length(item.media_specific_information) > 0xff)
			return null;

		buf.put('6s', local_if_mac_address);
		buf.put('!H', item.media_type);
		buf.put('B', length(item.media_specific_information));
		buf.put('*', item.media_specific_information);
	}

	return buf;
};

// 0x04 - Device bridging capability
// IEEE1905.1-2013
encoder[0x04] = (buf, bridging_tuples) => {
	if (type(bridging_tuples) != "array" || length(bridging_tuples) > 0xff)
		return null;

	buf.put('B', length(bridging_tuples));

	for (let mac_addresses in bridging_tuples) {
		if (type(mac_addresses) != "array" || length(mac_addresses) > 0xff)
			return null;

		buf.put('B', length(mac_addresses));

		for (let mac_address in mac_addresses) {
			const _mac_address = hexdec(match(mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

			if (_mac_address == null)
				return null;

			buf.put('6s', _mac_address);
		}
	}

	return buf;
};

// 0x06 - Non-1905 neighbor devices
// IEEE1905.1-2013
encoder[0x06] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const local_if_mac_address = hexdec(match(tlv.local_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (local_if_mac_address == null)
		return null;

	if (type(tlv.non_ieee1905_neighbors) != "array")
		return null;

	buf.put('6s', local_if_mac_address);

	for (let non_1905_neighbor_device_mac_address in tlv.non_ieee1905_neighbors) {
		const _non_1905_neighbor_device_mac_address = hexdec(match(non_1905_neighbor_device_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_non_1905_neighbor_device_mac_address == null)
			return null;

		buf.put('6s', _non_1905_neighbor_device_mac_address);
	}

	return buf;
};

// 0x07 - 1905 neighbor devices
// IEEE1905.1-2013
encoder[0x07] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const local_if_mac_address = hexdec(match(tlv.local_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (local_if_mac_address == null)
		return null;

	if (type(tlv.ieee1905_neighbors) != "array")
		return null;

	buf.put('6s', local_if_mac_address);

	for (let item in tlv.ieee1905_neighbors) {
		if (type(item) != "object")
			return null;

		const neighbor_al_mac_address = hexdec(match(item.neighbor_al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (neighbor_al_mac_address == null)
			return null;

		buf.put('6s', neighbor_al_mac_address);
		buf.put('B', 0
			| (item.bridges_present << 7)
		);
	}

	return buf;
};

// 0x08 - Link metric query
// IEEE1905.1-2013
encoder[0x08] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (!(tlv.query_type in [ 0x00, 0x01 ]))
		return null;

	let al_mac_address = null;

	if (tlv.al_mac_address != null) {
		al_mac_address = hexdec(match(tlv.al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (al_mac_address == null)
			return null;
	}

	if (!(tlv.link_metrics_requested in [ 0x00, 0x01, 0x02 ]))
		return null;

	buf.put('B', tlv.query_type);

	if (al_mac_address != null) {
		if (tlv.query_type == null)
			tlv.query_type = 1;

		if (al_mac_address != null)
			buf.put('6s', al_mac_address);
	}

	buf.put('B', tlv.link_metrics_requested);

	return buf;
};

// 0x09 - 1905.1 transmitter link metric
// IEEE1905.1-2013
encoder[0x09] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const transmitter_al_mac_address = hexdec(match(tlv.transmitter_al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (transmitter_al_mac_address == null)
		return null;

	const neighbor_al_mac_address = hexdec(match(tlv.neighbor_al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (neighbor_al_mac_address == null)
		return null;

	if (type(tlv.link_metrics) != "array")
		return null;

	buf.put('6s', transmitter_al_mac_address);
	buf.put('6s', neighbor_al_mac_address);

	for (let item in tlv.link_metrics) {
		if (type(item) != "object")
			return null;

		const local_if_mac_address = hexdec(match(item.local_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (local_if_mac_address == null)
			return null;

		const remote_if_mac_address = hexdec(match(item.remote_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (remote_if_mac_address == null)
			return null;

		if (!(item.media_type in [ 0x0000, 0x0001, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0200, 0x0201, 0x0300, 0xffff ]))
			return null;

		buf.put('6s', local_if_mac_address);
		buf.put('6s', remote_if_mac_address);
		buf.put('!H', item.media_type);
		buf.put('?', item.bridges_present);
		buf.put('!L', item.packet_errors);
		buf.put('!L', item.transmitted_packets);
		buf.put('!H', item.mac_throughput_capacity);
		buf.put('!H', item.link_availability);
		buf.put('!H', item.phy_rate);
	}

	return buf;
};

// 0x0a - 1905.1 receiver link metric
// IEEE1905.1-2013
encoder[0x0a] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const transmitter_al_mac_address = hexdec(match(tlv.transmitter_al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (transmitter_al_mac_address == null)
		return null;

	const neighbor_al_mac_address = hexdec(match(tlv.neighbor_al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (neighbor_al_mac_address == null)
		return null;

	if (type(tlv.link_metrics) != "array")
		return null;

	buf.put('6s', transmitter_al_mac_address);
	buf.put('6s', neighbor_al_mac_address);

	for (let item in tlv.link_metrics) {
		if (type(item) != "object")
			return null;

		const local_if_mac_address = hexdec(match(item.local_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (local_if_mac_address == null)
			return null;

		const remote_if_mac_address = hexdec(match(item.remote_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (remote_if_mac_address == null)
			return null;

		if (!(item.media_type in [ 0x0000, 0x0001, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0200, 0x0201, 0x0300, 0xffff ]))
			return null;

		buf.put('6s', local_if_mac_address);
		buf.put('6s', remote_if_mac_address);
		buf.put('!H', item.media_type);
		buf.put('!L', item.packet_errors);
		buf.put('!L', item.received_packets);
		buf.put('B', item.rssi);
	}

	return buf;
};

// 0x0b - Vendor specific
// IEEE1905.1-2013
encoder[0x0b] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.vendor_specific_oui) != "string" || length(tlv.vendor_specific_oui) > 3)
		return null;

	if (type(tlv.vendor_specific_information) != "string")
		return null;

	buf.put('3s', tlv.vendor_specific_oui);
	buf.put('*', tlv.vendor_specific_information);

	return buf;
};

// 0x0c - 1905.1 link metric result code
// IEEE1905.1-2013
encoder[0x0c] = (buf, result_code) => {
	if (!(result_code in [ 0x00 ]))
		return null;

	buf.put('B', result_code);

	return buf;
};

// 0x0d - Searched Role
// IEEE1905.1-2013
encoder[0x0d] = (buf, role) => {
	if (!(role in [ 0x00 ]))
		return null;

	buf.put('B', role);

	return buf;
};

// 0x0e - Autoconfig Frequency Band
// IEEE1905.1-2013
encoder[0x0e] = (buf, frequency_band) => {

	buf.put('B', frequency_band);

	return buf;
};

// 0x0f - Supported Role
// IEEE1905.1-2013
encoder[0x0f] = (buf, type_of_role) => {

	buf.put('B', type_of_role);

	return buf;
};

// 0x10 - Supported Frequency Band
// IEEE1905.1-2013
encoder[0x10] = (buf, frequency_band) => {

	buf.put('B', frequency_band);

	return buf;
};

// 0x11 - WSC
// IEEE1905.1-2013
encoder[0x11] = (buf, payload) => buf.put('*', payload),

// 0x12 - Push_Button_Event notification
// IEEE1905.1-2013
encoder[0x12] = (buf, media_types) => {
	if (type(media_types) != "array" || length(media_types) > 0xff)
		return null;

	buf.put('B', length(media_types));

	for (let item in media_types) {
		if (type(item) != "object")
			return null;

		if (!(item.media_type in [ 0x0000, 0x0001, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0200, 0x0201, 0x0300, 0xffff ]))
			return null;

		if (type(item.media_specific_information) != "string" || length(item.media_specific_information) > 0xff)
			return null;

		buf.put('!H', item.media_type);
		buf.put('B', length(item.media_specific_information));
		buf.put('*', item.media_specific_information);
	}

	return buf;
};

// 0x13 - Push_Button_Join notification
// IEEE1905.1-2013
encoder[0x13] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const al_id = hexdec(match(tlv.al_id, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (al_id == null)
		return null;

	const transmitter_if_mac_address = hexdec(match(tlv.transmitter_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (transmitter_if_mac_address == null)
		return null;

	const neighbor_if_mac_address = hexdec(match(tlv.neighbor_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (neighbor_if_mac_address == null)
		return null;

	buf.put('6s', al_id);
	buf.put('!H', tlv.message_identifier);
	buf.put('6s', transmitter_if_mac_address);
	buf.put('6s', neighbor_if_mac_address);

	return buf;
};

// 0x14 - Generic Phy device information
// IEEE1905.1a-2014
encoder[0x14] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const al_mac_address = hexdec(match(tlv.al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (al_mac_address == null)
		return null;

	if (type(tlv.local_interfaces) != "array" || length(tlv.local_interfaces) > 0xff)
		return null;

	buf.put('6s', al_mac_address);
	buf.put('B', length(tlv.local_interfaces));

	for (let item in tlv.local_interfaces) {
		if (type(item) != "object")
			return null;

		const local_if_mac_address = hexdec(match(item.local_if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (local_if_mac_address == null)
			return null;

		if (type(item.phy_oui) != "string" || length(item.phy_oui) > 3)
			return null;

		if (type(item.phy_variant_name) != "string" || length(item.phy_variant_name) > 32)
			return null;

		if (type(item.phy_description_url) != "string" || length(item.phy_description_url) > 0xff)
			return null;

		if (type(item.media_specific_information) != "string" || length(item.media_specific_information) > 0xff)
			return null;

		buf.put('6s', local_if_mac_address);
		buf.put('3s', item.phy_oui);
		buf.put('B', item.phy_variant);
		buf.put('32s', item.phy_variant_name);
		buf.put('B', length(item.phy_description_url));
		buf.put('B', length(item.media_specific_information));
		buf.put('*', item.phy_description_url);
		buf.put('*', item.media_specific_information);
	}

	return buf;
};

// 0x15 - Device identification
// IEEE1905.1a-2014
encoder[0x15] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.friendly_name) != "string" || length(tlv.friendly_name) > 64)
		return null;

	if (type(tlv.manufacturer_name) != "string" || length(tlv.manufacturer_name) > 64)
		return null;

	if (type(tlv.manufacturer_model) != "string" || length(tlv.manufacturer_model) > 64)
		return null;

	buf.put('64s', tlv.friendly_name);
	buf.put('64s', tlv.manufacturer_name);
	buf.put('64s', tlv.manufacturer_model);

	return buf;
};

// 0x16 - Control URL
// IEEE1905.1a-2014
encoder[0x16] = (buf, payload) => buf.put('*', payload),

// 0x17 - IPv4
// IEEE1905.1a-2014
encoder[0x17] = (buf, interfaces) => {
	if (type(interfaces) != "array" || length(interfaces) > 0xff)
		return null;

	buf.put('B', length(interfaces));

	for (let item in interfaces) {
		if (type(item) != "object")
			return null;

		const if_mac_address = hexdec(match(item.if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (if_mac_address == null)
			return null;

		if (type(item.addresses) != "array" || length(item.addresses) > 0xff)
			return null;

		buf.put('6s', if_mac_address);
		buf.put('B', length(item.addresses));

		for (let item2 in item.addresses) {
			if (type(item2) != "object")
				return null;

			if (!(item2.ipv4addr_type in [ 0, 1, 2, 3 ]))
				return null;

			const address = iptoarr(item2.address);

			if (length(address) != 4)
				return null;

			const dhcp_server = iptoarr(item2.dhcp_server);

			if (length(dhcp_server) != 4)
				return null;

			buf.put('B', item2.ipv4addr_type);
			buf.put('4B', ...address);
			buf.put('4B', ...dhcp_server);
		}
	}

	return buf;
};

// 0x18 - IPv6
// IEEE1905.1a-2014
encoder[0x18] = (buf, interfaces) => {
	if (type(interfaces) != "array" || length(interfaces) > 0xff)
		return null;

	buf.put('B', length(interfaces));

	for (let item in interfaces) {
		if (type(item) != "object")
			return null;

		const if_mac_address = hexdec(match(item.if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (if_mac_address == null)
			return null;

		const linklocal_address = iptoarr(item.linklocal_address);

		if (length(linklocal_address) != 16)
			return null;

		if (type(item.other_addresses) != "array" || length(item.other_addresses) > 0xff)
			return null;

		buf.put('6s', if_mac_address);
		buf.put('16B', ...linklocal_address);
		buf.put('B', length(item.other_addresses));

		for (let item2 in item.other_addresses) {
			if (type(item2) != "object")
				return null;

			if (!(item2.ipv6addr_type in [ 0, 1, 2, 3 ]))
				return null;

			const address = iptoarr(item2.address);

			if (length(address) != 16)
				return null;

			const origin = iptoarr(item2.origin);

			if (length(origin) != 16)
				return null;

			buf.put('B', item2.ipv6addr_type);
			buf.put('16B', ...address);
			buf.put('16B', ...origin);
		}
	}

	return buf;
};

// 0x19 - Push Button Generic Phy Event
// IEEE1905.1a-2014
encoder[0x19] = (buf, phy_media_types) => {
	if (type(phy_media_types) != "array" || length(phy_media_types) > 0xff)
		return null;

	buf.put('B', length(phy_media_types));

	for (let item in phy_media_types) {
		if (type(item) != "object")
			return null;

		if (type(item.phy_oui) != "string" || length(item.phy_oui) > 3)
			return null;

		if (type(item.media_specific_information) != "string" || length(item.media_specific_information) > 0xff)
			return null;

		buf.put('3s', item.phy_oui);
		buf.put('B', item.phy_variant);
		buf.put('B', length(item.media_specific_information));
		buf.put('*', item.media_specific_information);
	}

	return buf;
};

// 0x1a - 1905 profile version
// IEEE1905.1a-2014
encoder[0x1a] = (buf, ieee1905_profile) => {
	if (!(ieee1905_profile in [ 0x00, 0x01 ]))
		return null;

	buf.put('B', ieee1905_profile);

	return buf;
};

// 0x1b - Power off interface
// IEEE1905.1a-2014
encoder[0x1b] = (buf, interfaces) => {
	if (type(interfaces) != "array" || length(interfaces) > 0xff)
		return null;

	buf.put('B', length(interfaces));

	for (let item in interfaces) {
		if (type(item) != "object")
			return null;

		const if_mac_address = hexdec(match(item.if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (if_mac_address == null)
			return null;

		if (!(item.media_type in [ 0x0000, 0x0001, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0200, 0x0201, 0x0300, 0xffff ]))
			return null;

		if (type(item.phy_oui) != "string" || length(item.phy_oui) > 3)
			return null;

		if (type(item.media_specific_information) != "string" || length(item.media_specific_information) > 0xff)
			return null;

		buf.put('6s', if_mac_address);
		buf.put('!H', item.media_type);
		buf.put('3s', item.phy_oui);
		buf.put('B', length(item.media_specific_information));
		buf.put('B', item.media_specific_information_length);
		buf.put('*', item.media_specific_information);
	}

	return buf;
};

// 0x1c - Interface power change information
// IEEE1905.1a-2014
encoder[0x1c] = (buf, interfaces) => {
	if (type(interfaces) != "array" || length(interfaces) > 0xff)
		return null;

	buf.put('B', length(interfaces));

	for (let item in interfaces) {
		if (type(item) != "object")
			return null;

		const if_mac_address = hexdec(match(item.if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (if_mac_address == null)
			return null;

		if (!(item.power_state in [ 0x00, 0x01, 0x02 ]))
			return null;

		buf.put('6s', if_mac_address);
		buf.put('B', item.power_state);
	}

	return buf;
};

// 0x1d - Interface power change status
// IEEE1905.1a-2014
encoder[0x1d] = (buf, interfaces) => {
	if (type(interfaces) != "array" || length(interfaces) > 0xff)
		return null;

	buf.put('B', length(interfaces));

	for (let item in interfaces) {
		if (type(item) != "object")
			return null;

		const if_mac_address = hexdec(match(item.if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (if_mac_address == null)
			return null;

		if (!(item.change_state in [ 0x00, 0x01, 0x02 ]))
			return null;

		buf.put('6s', if_mac_address);
		buf.put('B', item.change_state);
	}

	return buf;
};

// 0x1e - L2 neighbor device
// IEEE1905.1a-2014
encoder[0x1e] = (buf, interfaces) => {
	if (type(interfaces) != "array" || length(interfaces) > 0xff)
		return null;

	buf.put('B', length(interfaces));

	for (let item in interfaces) {
		if (type(item) != "object")
			return null;

		const if_mac_address = hexdec(match(item.if_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (if_mac_address == null)
			return null;

		if (type(item.neighbors) != "array" || length(item.neighbors) > 0xffff)
			return null;

		buf.put('6s', if_mac_address);
		buf.put('!H', length(item.neighbors));

		for (let item2 in item.neighbors) {
			if (type(item2) != "object")
				return null;

			const neighbor_mac_address = hexdec(match(item2.neighbor_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

			if (neighbor_mac_address == null)
				return null;

			if (type(item2.behind_mac_addresses) != "array" || length(item2.behind_mac_addresses) > 0xffff)
				return null;

			buf.put('6s', neighbor_mac_address);
			buf.put('!H', length(item2.behind_mac_addresses));

			for (let behind_mac_address in item2.behind_mac_addresses) {
				const _behind_mac_address = hexdec(match(behind_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

				if (_behind_mac_address == null)
					return null;

				buf.put('6s', _behind_mac_address);
			}
		}
	}

	return buf;
};

// 0x80 - Supported Service
// Wi-Fi EasyMesh
encoder[0x80] = (buf, services) => {
	if (type(services) != "array" || length(services) > 0xff)
		return null;

	buf.put('B', length(services));

	for (let supported_service in services) {
		if (!(supported_service in [ 0x00, 0x01 ]))
			return null;

		buf.put('B', supported_service);
	}

	return buf;
};

// 0x81 - Searched Service
// Wi-Fi EasyMesh
encoder[0x81] = (buf, services) => {
	if (type(services) != "array" || length(services) > 0xff)
		return null;

	buf.put('B', length(services));

	for (let searched_service in services) {
		if (!(searched_service in [ 0x00 ]))
			return null;

		buf.put('B', searched_service);
	}

	return buf;
};

// 0x82 - AP Radio Identifier
// Wi-Fi EasyMesh
encoder[0x82] = (buf, radio_unique_identifier) => {
	const _radio_unique_identifier = hexdec(match(radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (_radio_unique_identifier == null)
		return null;

	buf.put('6s', _radio_unique_identifier);

	return buf;
};

// 0x83 - AP Operational BSS
// Wi-Fi EasyMesh
encoder[0x83] = (buf, radios) => {
	if (type(radios) != "array" || length(radios) > 0xff)
		return null;

	buf.put('B', length(radios));

	for (let item in radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (type(item.bss) != "array" || length(item.bss) > 0xff)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', length(item.bss));

		for (let item2 in item.bss) {
			if (type(item2) != "object")
				return null;

			const mac_address = hexdec(match(item2.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

			if (mac_address == null)
				return null;

			if (type(item2.ssid) != "string" || length(item2.ssid) > 0xff)
				return null;

			buf.put('6s', mac_address);
			buf.put('B', length(item2.ssid));
			buf.put('*', item2.ssid);
		}
	}

	return buf;
};

// 0x84 - Associated Clients
// Wi-Fi EasyMesh
encoder[0x84] = (buf, bss) => {
	if (type(bss) != "array" || length(bss) > 0xff)
		return null;

	buf.put('B', length(bss));

	for (let item in bss) {
		if (type(item) != "object")
			return null;

		const bssid = hexdec(match(item.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (bssid == null)
			return null;

		if (type(item.clients) != "array" || length(item.clients) > 0xffff)
			return null;

		buf.put('6s', bssid);
		buf.put('!H', length(item.clients));

		for (let item2 in item.clients) {
			if (type(item2) != "object")
				return null;

			const mac_address = hexdec(match(item2.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

			if (mac_address == null)
				return null;

			if (type(item2.last_association) != "int" || item2.last_association < 0 || item2.last_association > 65535)
				return null;

			buf.put('6s', mac_address);
			buf.put('!H', item2.last_association);
		}
	}

	return buf;
};

// 0x85 - AP Radio Basic Capabilities
// Wi-Fi EasyMesh
encoder[0x85] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.opclasses_supported) != "array" || length(tlv.opclasses_supported) > 0xff)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', tlv.max_bss_supported);
	buf.put('B', length(tlv.opclasses_supported));

	for (let item in tlv.opclasses_supported) {
		if (type(item) != "object")
			return null;

		if (type(item.statically_non_operable_channels) != "array" || length(item.statically_non_operable_channels) > 0xff)
			return null;

		buf.put('B', item.opclass);
		buf.put('B', item.max_txpower_eirp);
		buf.put('B', length(item.statically_non_operable_channels));

		for (let channel in item.statically_non_operable_channels) {
			buf.put('B', channel);
		}
	}

	return buf;
};

// 0x86 - AP HT Capabilities
// Wi-Fi EasyMesh
encoder[0x86] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (!(tlv.max_supported_tx_spatial_streams in [ 0b00, 0b01, 0b10, 0b11 ]))
		return null;

	if (!(tlv.max_supported_rx_spatial_streams in [ 0b00, 0b01, 0b10, 0b11 ]))
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', 0
		| ((tlv.max_supported_tx_spatial_streams & 0b00000011) << 6)
		| ((tlv.max_supported_rx_spatial_streams & 0b00000011) << 4)
		| (tlv.short_gi_support_20mhz << 3)
		| (tlv.short_gi_support_40mhz << 2)
		| (tlv.ht_support_40mhz << 1)
	);

	return buf;
};

// 0x87 - AP VHT Capabilities
// Wi-Fi EasyMesh
encoder[0x87] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (!(tlv.max_supported_tx_spatial_streams in [ 0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111 ]))
		return null;

	if (!(tlv.max_supported_rx_spatial_streams in [ 0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111 ]))
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('!H', tlv.supported_vht_tx_mcs);
	buf.put('!H', tlv.supported_vht_rx_mcs);
	buf.put('B', 0
		| ((tlv.max_supported_tx_spatial_streams & 0b00000111) << 5)
		| ((tlv.max_supported_rx_spatial_streams & 0b00000111) << 2)
		| (tlv.short_gi_support_80mhz << 1)
		| (tlv.short_gi_support_160mhz_8080mhz << 0)
	);

	buf.put('B', 0
		| (tlv.vht_support_8080mhz << 7)
		| (tlv.vht_support_160mhz << 6)
		| (tlv.su_beamformer_capable << 5)
		| (tlv.mu_beamformer_capable << 4)
	);

	return buf;
};

// 0x88 - AP HE Capabilities
// Wi-Fi EasyMesh
encoder[0x88] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.supported_he_mcs) != "string" || length(tlv.supported_he_mcs) > 0xff)
		return null;

	if (!(tlv.max_supported_tx_spatial_streams in [ 0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111 ]))
		return null;

	if (!(tlv.max_supported_rx_spatial_streams in [ 0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111 ]))
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', length(tlv.supported_he_mcs));
	buf.put('*', tlv.supported_he_mcs);
	buf.put('B', 0
		| ((tlv.max_supported_tx_spatial_streams & 0b00000111) << 5)
		| ((tlv.max_supported_rx_spatial_streams & 0b00000111) << 2)
		| (tlv.he_support_8080mhz << 1)
		| (tlv.he_support_160mhz << 0)
	);

	buf.put('B', 0
		| (tlv.su_beamformer_capable << 7)
		| (tlv.mu_beamformer_capable << 6)
		| (tlv.ul_mu_mimo_capable << 5)
		| (tlv.ul_mu_mimo_ofdma_capable << 4)
		| (tlv.dl_mu_mimo_ofdma_capable << 3)
		| (tlv.ul_ofdma_capable << 2)
		| (tlv.dl_ofdma_capable << 1)
	);

	return buf;
};

// 0x89 - Steering Policy
// Wi-Fi EasyMesh
encoder[0x89] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.local_steering_disallowed_sta) != "array" || length(tlv.local_steering_disallowed_sta) > 0xff)
		return null;

	if (type(tlv.btm_steering_disallowed_sta) != "array" || length(tlv.btm_steering_disallowed_sta) > 0xff)
		return null;

	if (type(tlv.radios) != "array" || length(tlv.radios) > 0xff)
		return null;

	buf.put('B', length(tlv.local_steering_disallowed_sta));

	for (let sta_mac_address in tlv.local_steering_disallowed_sta) {
		const _sta_mac_address = hexdec(match(sta_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_sta_mac_address == null)
			return null;

		buf.put('6s', _sta_mac_address);
	}

	buf.put('B', length(tlv.btm_steering_disallowed_sta));

	for (let sta_mac_address in tlv.btm_steering_disallowed_sta) {
		const _sta_mac_address = hexdec(match(sta_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_sta_mac_address == null)
			return null;

		buf.put('6s', _sta_mac_address);
	}

	buf.put('B', length(tlv.radios));

	for (let item in tlv.radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (!(item.steering_policy in [ 0x00, 0x01, 0x02 ]))
			return null;

		if (type(item.rcpi_steering_threshold) != "int" || item.rcpi_steering_threshold < 0 || item.rcpi_steering_threshold > 220)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', item.steering_policy);
		buf.put('B', item.channel_utilization_threshold);
		buf.put('B', item.rcpi_steering_threshold);
	}

	return buf;
};

// 0x8a - Metric Reporting Policy
// Wi-Fi EasyMesh
encoder[0x8a] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.ap_metrics_reporting_interval) != "int" || tlv.ap_metrics_reporting_interval < 0 || tlv.ap_metrics_reporting_interval > 255)
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.radios) != "array" || length(tlv.radios) > 0xff)
		return null;

	buf.put('B', tlv.ap_metrics_reporting_interval);
	buf.put('B', length(tlv.radios));
	buf.put('6s', radio_unique_identifier);

	for (let item in tlv.radios) {
		if (type(item) != "object")
			return null;

		if (type(item.sta_metrics_reporting_rcpi_threshold) != "int" || item.sta_metrics_reporting_rcpi_threshold < 0 || item.sta_metrics_reporting_rcpi_threshold > 220)
			return null;

		buf.put('B', item.sta_metrics_reporting_rcpi_threshold);
		buf.put('B', item.sta_metrics_reporting_rcpi_hysteresis_margin_override);
		buf.put('B', item.ap_metrics_channel_utilization_reporting_threshold);
		buf.put('B', 0
			| (item.associated_sta_traffic_stats_inclusion_policy << 7)
			| (item.associated_sta_link_metrics_inclusion_policy << 6)
			| (item.associated_wifi6_sta_status_inclusion_policy << 5)
		);
	}

	return buf;
};

// 0x8b - Channel Preference
// Wi-Fi EasyMesh
encoder[0x8b] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.opclasses) != "array" || length(tlv.opclasses) > 0xff)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', length(tlv.opclasses));

	for (let item in tlv.opclasses) {
		if (type(item) != "object")
			return null;

		if (type(item.channels) != "array")
			return null;

		if (type(item.preference) != "int" || item.preference < 0 || item.preference > 15)
			return null;

		if (!(item.reason_code in [ 0b0000, 0b0001, 0b0010, 0b0011, 0b0100, 0b0101, 0b0110, 0b0111, 0b1000, 0b1001, 0b1010, 0b1011, 0b1100 ]))
			return null;

		buf.put('B', item.opclass);
		buf.put('B', length(item.channels));

		for (let item2 in item.channels) {
			if (type(item2) != "int" || item2 < 0 || item2 > 0xff)
				return null;

			buf.put('B', item2);
		}

		buf.put('B', 0
			| ((item.preference & 0b00001111) << 4)
			| ((item.reason_code & 0b00001111) << 0)
		);
	}

	return buf;
};

// 0x8c - Radio Operation Restriction
// Wi-Fi EasyMesh
encoder[0x8c] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.opclasses) != "array" || length(tlv.opclasses) > 0xff)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', length(tlv.opclasses));

	for (let item in tlv.opclasses) {
		if (type(item) != "object")
			return null;

		if (type(item.channels) != "array" || length(item.channels) > 0xff)
			return null;

		buf.put('B', item.opclass);
		buf.put('B', length(item.channels));

		for (let item2 in item.channels) {
			if (type(item2) != "object")
				return null;

			buf.put('B', item2.channel);
			buf.put('B', item2.minimum_frequency_separation);
		}
	}

	return buf;
};

// 0x8d - Transmit Power Limit
// Wi-Fi EasyMesh
encoder[0x8d] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', tlv.txpower_limit_eirp);

	return buf;
};

// 0x8e - Channel Selection Response
// Wi-Fi EasyMesh
encoder[0x8e] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (!(tlv.channel_selection_response_code in [ 0x00, 0x01, 0x02, 0x03 ]))
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', tlv.channel_selection_response_code);

	return buf;
};

// 0x8f - Operating Channel Report
// Wi-Fi EasyMesh
encoder[0x8f] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.current_opclass) != "array" || length(tlv.current_opclass) > 0xff)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', length(tlv.current_opclass));

	for (let item in tlv.current_opclass) {
		if (type(item) != "object")
			return null;

		buf.put('B', item.opclass);
		buf.put('B', item.current_operating_channel);
	}

	buf.put('B', tlv.current_txpower_eirp);

	return buf;
};

// 0x90 - Client Info
// Wi-Fi EasyMesh
encoder[0x90] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	buf.put('6s', bssid);
	buf.put('6s', mac_address);

	return buf;
};

// 0x91 - Client Capability Report
// Wi-Fi EasyMesh
encoder[0x91] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (!(tlv.result_code in [ 0x00, 0x01 ]))
		return null;

	if (tlv.frame_body != null && (type(tlv.frame_body) != "string"))
		return null;

	buf.put('B', tlv.result_code);

	if (tlv.frame_body != null) {
		if (tlv.result_code == null)
			tlv.result_code = 0;

		if (tlv.frame_body != null) {
			buf.put('*', tlv.frame_body);
		}
	}

	return buf;
};

// 0x92 - Client Association Event
// Wi-Fi EasyMesh
encoder[0x92] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	buf.put('6s', mac_address);
	buf.put('6s', bssid);
	buf.put('B', 0
		| (tlv.association_event << 7)
	);

	return buf;
};

// 0x93 - AP Metric Query
// Wi-Fi EasyMesh
encoder[0x93] = (buf, bssids) => {
	if (type(bssids) != "array" || length(bssids) > 0xff)
		return null;

	buf.put('B', length(bssids));

	for (let bssid in bssids) {
		const _bssid = hexdec(match(bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_bssid == null)
			return null;

		buf.put('6s', _bssid);
	}

	return buf;
};

// 0x94 - AP Metrics
// Wi-Fi EasyMesh
encoder[0x94] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	if (tlv.esp_be != null && (type(tlv.esp_be) != "string" || length(tlv.esp_be) > 3))
		return null;

	if (tlv.esp_bk != null && (type(tlv.esp_bk) != "string" || length(tlv.esp_bk) > 3))
		return null;

	if (tlv.esp_vo != null && (type(tlv.esp_vo) != "string" || length(tlv.esp_vo) > 3))
		return null;

	if (tlv.esp_vi != null && (type(tlv.esp_vi) != "string" || length(tlv.esp_vi) > 3))
		return null;

	buf.put('6s', bssid);
	buf.put('B', tlv.channel_utilization);
	buf.put('!H', tlv.sta_count);
	buf.put('B', 0
		| (tlv.include_esp_be << 7)
		| (tlv.include_esp_bk << 6)
		| (tlv.include_esp_vo << 5)
		| (tlv.include_esp_vi << 4)
	);

	if (tlv.esp_be != null) {
		if (tlv.include_esp_be == null)
			tlv.include_esp_be = 1;

		if (tlv.esp_be != null) {
			buf.put('3s', tlv.esp_be);
		}
	}

	if (tlv.esp_bk != null) {
		if (tlv.include_esp_bk == null)
			tlv.include_esp_bk = 1;

		if (tlv.esp_bk != null) {
			buf.put('3s', tlv.esp_bk);
		}
	}

	if (tlv.esp_vo != null) {
		if (tlv.include_esp_vo == null)
			tlv.include_esp_vo = 1;

		if (tlv.esp_vo != null) {
			buf.put('3s', tlv.esp_vo);
		}
	}

	if (tlv.esp_vi != null) {
		if (tlv.include_esp_vi == null)
			tlv.include_esp_vi = 1;

		if (tlv.esp_vi != null) {
			buf.put('3s', tlv.esp_vi);
		}
	}

	return buf;
};

// 0x95 - STA MAC Address Type
// Wi-Fi EasyMesh
encoder[0x95] = (buf, mac_address) => {
	const _mac_address = hexdec(match(mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (_mac_address == null)
		return null;

	buf.put('6s', _mac_address);

	return buf;
};

// 0x96 - Associated STA Link Metrics
// Wi-Fi EasyMesh
encoder[0x96] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	if (type(tlv.bssids) != "array" || length(tlv.bssids) > 0xff)
		return null;

	buf.put('6s', mac_address);
	buf.put('B', length(tlv.bssids));

	for (let item in tlv.bssids) {
		if (type(item) != "object")
			return null;

		const bssid = hexdec(match(item.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (bssid == null)
			return null;

		const estimated_downlink_mac_data_rate = hexdec(match(item.estimated_downlink_mac_data_rate, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (estimated_downlink_mac_data_rate == null)
			return null;

		const estimated_uplink_mac_data_rate = hexdec(match(item.estimated_uplink_mac_data_rate, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (estimated_uplink_mac_data_rate == null)
			return null;

		if (type(item.uplink_rcpi) != "int" || item.uplink_rcpi < 0 || item.uplink_rcpi > 220)
			return null;

		buf.put('6s', bssid);
		buf.put('!L', item.time_delta);
		buf.put('6s', estimated_downlink_mac_data_rate);
		buf.put('6s', estimated_uplink_mac_data_rate);
		buf.put('B', item.uplink_rcpi);
	}

	return buf;
};

// 0x97 - Unassociated STA Link Metrics Query
// Wi-Fi EasyMesh
encoder[0x97] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.channels) != "array" || length(tlv.channels) > 0xff)
		return null;

	buf.put('B', tlv.opclass);
	buf.put('B', length(tlv.channels));

	for (let item in tlv.channels) {
		if (type(item) != "object")
			return null;

		if (type(item.sta_mac_addresses) != "array" || length(item.sta_mac_addresses) > 0xff)
			return null;

		buf.put('B', item.channel);
		buf.put('B', length(item.sta_mac_addresses));

		for (let sta_mac_address in item.sta_mac_addresses) {
			const _sta_mac_address = hexdec(match(sta_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

			if (_sta_mac_address == null)
				return null;

			buf.put('6s', _sta_mac_address);
		}
	}

	return buf;
};

// 0x98 - Unassociated STA Link Metrics Response
// Wi-Fi EasyMesh
encoder[0x98] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.sta_entries) != "array" || length(tlv.sta_entries) > 0xff)
		return null;

	buf.put('B', tlv.opclass);
	buf.put('B', length(tlv.sta_entries));

	for (let item in tlv.sta_entries) {
		if (type(item) != "object")
			return null;

		const mac_address = hexdec(match(item.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (mac_address == null)
			return null;

		if (type(item.uplink_rcpi) != "int" || item.uplink_rcpi < 0 || item.uplink_rcpi > 220)
			return null;

		buf.put('6s', mac_address);
		buf.put('B', item.channel);
		buf.put('!L', item.time_delta);
		buf.put('B', item.uplink_rcpi);
	}

	return buf;
};

// 0x99 - Beacon Metrics Query
// Wi-Fi EasyMesh
encoder[0x99] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	if (type(tlv.ssid) != "string" || length(tlv.ssid) > 0xff)
		return null;

	if (type(tlv.ap_channel_reports) != "array" || length(tlv.ap_channel_reports) > 0xff)
		return null;

	if (type(tlv.element_list) != "array")
		return null;

	buf.put('6s', mac_address);
	buf.put('B', tlv.opclass);
	buf.put('B', tlv.channel);
	buf.put('6s', bssid);
	buf.put('B', tlv.reporting_detail_value);
	buf.put('B', length(tlv.ssid));
	buf.put('*', tlv.ssid);
	buf.put('B', length(tlv.ap_channel_reports));

	for (let item in tlv.ap_channel_reports) {
		if (type(item) != "object")
			return null;

		if (type(item.channels) != "array")
			return null;

		buf.put('B', length(item.channels));
		buf.put('B', item.opclass);

		for (let item2 in item.channels) {
			if (type(item2) != "int" || item2 < 0 || item2 > 0xff)
				return null;

			buf.put('B', item2);
		}
	}

	buf.put('B', length(tlv.element_list));

	for (let item in tlv.element_list) {
		if (type(item) != "int" || item < 0 || item > 0xff)
			return null;

		buf.put('B', item);
	}

	return buf;
};

// 0x9a - Beacon Metrics Response
// Wi-Fi EasyMesh
encoder[0x9a] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	if (type(tlv.measurement_report_elements) != "array" || length(tlv.measurement_report_elements) > 0xff)
		return null;

	buf.put('6s', mac_address);
	buf.put('B', length(tlv.measurement_report_elements));

	for (let item in tlv.measurement_report_elements) {
		if (type(item) != "object")
			return null;

		if (type(item.report_data) != "string" || length(item.report_data) > 0xff - 18446744073709551613)
			return null;

		buf.put('B', item.id);
		buf.put('B', length(item.report_data));
		buf.put('B', item.token);
		buf.put('B', item.report_mode);
		buf.put('B', item.type);
		buf.put('*', item.report_data);
	}

	return buf;
};

// 0x9b - Steering Request
// Wi-Fi EasyMesh
encoder[0x9b] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	if (type(tlv.sta_list) != "array" || length(tlv.sta_list) > 0xff)
		return null;

	if (type(tlv.target_bssid_list) != "array" || length(tlv.target_bssid_list) > 0xff)
		return null;

	buf.put('6s', bssid);
	buf.put('B', 0
		| (tlv.request_mode << 7)
		| (tlv.btm_disassociation_imminent_bit << 6)
		| (tlv.btm_abridged_bit << 5)
	);

	buf.put('!H', tlv.steering_opportunity_window);
	buf.put('!H', tlv.btm_disassociation_timer);
	buf.put('B', length(tlv.sta_list));

	for (let sta_mac_address in tlv.sta_list) {
		const _sta_mac_address = hexdec(match(sta_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_sta_mac_address == null)
			return null;

		buf.put('6s', _sta_mac_address);
	}

	buf.put('B', length(tlv.target_bssid_list));

	for (let item in tlv.target_bssid_list) {
		if (type(item) != "object")
			return null;

		const target_bssid = hexdec(match(item.target_bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (target_bssid == null)
			return null;

		buf.put('6s', target_bssid);
		buf.put('B', item.target_bss_opclass);
		buf.put('B', item.target_bss_channel);
	}

	return buf;
};

// 0x9c - Steering BTM Report
// Wi-Fi EasyMesh
encoder[0x9c] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	const sta_mac_address = hexdec(match(tlv.sta_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (sta_mac_address == null)
		return null;

	const target_bssid = hexdec(match(tlv.target_bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (target_bssid == null)
		return null;

	buf.put('6s', bssid);
	buf.put('6s', sta_mac_address);
	buf.put('B', tlv.btm_status_code);
	buf.put('6s', target_bssid);

	return buf;
};

// 0x9d - Client Association Control Request
// Wi-Fi EasyMesh
encoder[0x9d] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	if (!(tlv.association_control in [ 0x00, 0x01, 0x02, 0x03 ]))
		return null;

	if (type(tlv.sta_list) != "array" || length(tlv.sta_list) > 0xff)
		return null;

	buf.put('6s', bssid);
	buf.put('B', tlv.association_control);
	buf.put('!H', tlv.validity_period);
	buf.put('B', length(tlv.sta_list));

	for (let sta_mac_address in tlv.sta_list) {
		const _sta_mac_address = hexdec(match(sta_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_sta_mac_address == null)
			return null;

		buf.put('6s', _sta_mac_address);
	}

	return buf;
};

// 0x9e - Backhaul Steering Request
// Wi-Fi EasyMesh
encoder[0x9e] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	buf.put('6s', mac_address);
	buf.put('6s', bssid);
	buf.put('B', tlv.opclass);
	buf.put('B', tlv.channel);

	return buf;
};

// 0x9f - Backhaul Steering Response
// Wi-Fi EasyMesh
encoder[0x9f] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	if (!(tlv.result_code in [ 0x00, 0x01 ]))
		return null;

	buf.put('6s', mac_address);
	buf.put('6s', bssid);
	buf.put('B', tlv.result_code);

	return buf;
};

// 0xa0 - Higher Layer Data
// Wi-Fi EasyMesh
encoder[0xa0] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.data) != "string")
		return null;

	buf.put('B', tlv.protocol);
	buf.put('*', tlv.data);

	return buf;
};

// 0xa1 - AP Capability
// Wi-Fi EasyMesh
encoder[0xa1] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	buf.put('B', 0
		| (tlv.onchannel_unassoc_sta_metrics << 7)
		| (tlv.offchannel_unassoc_sta_metrics << 6)
		| (tlv.agent_initiated_rcpi_steering << 5)
	);

	return buf;
};

// 0xa2 - Associated STA Traffic Stats
// Wi-Fi EasyMesh
encoder[0xa2] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	buf.put('6s', mac_address);
	buf.put('!L', tlv.bytes_sent);
	buf.put('!L', tlv.bytes_received);
	buf.put('!L', tlv.packets_sent);
	buf.put('!L', tlv.packets_received);
	buf.put('!L', tlv.tx_packets_errors);
	buf.put('!L', tlv.rx_packets_errors);
	buf.put('!L', tlv.retransmission_count);

	return buf;
};

// 0xa3 - Error Code
// Wi-Fi EasyMesh
encoder[0xa3] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (!(tlv.reason_code in [ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 ]))
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	buf.put('B', tlv.reason_code);
	buf.put('6s', mac_address);

	return buf;
};

// 0xa4 - Channel Scan Reporting Policy
// Wi-Fi EasyMesh
encoder[0xa4] = (buf, report_independent_channel_scans) => {

	buf.put('B', 0
		| (report_independent_channel_scans << 7)
	);

	return buf;
};

// 0xa5 - Channel Scan Capabilities
// Wi-Fi EasyMesh
encoder[0xa5] = (buf, radios) => {
	if (type(radios) != "array" || length(radios) > 0xff)
		return null;

	buf.put('B', length(radios));

	for (let item in radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (!(item.scan_impact in [ 0x00, 0x01, 0x02, 0x03 ]))
			return null;

		if (type(item.opclass) != "array" || length(item.opclass) > 0xff)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', 0
			| (item.on_boot_only << 7)
			| ((item.scan_impact & 0b00000011) << 5)
		);

		buf.put('!L', item.minimum_scan_interval);
		buf.put('B', length(item.opclass));

		for (let item2 in item.opclass) {
			if (type(item2) != "object")
				return null;

			if (type(item2.channels) != "array")
				return null;

			buf.put('B', item2.opclass);
			buf.put('B', length(item2.channels));

			for (let item3 in item2.channels) {
				if (type(item3) != "int" || item3 < 0 || item3 > 0xff)
					return null;

				buf.put('B', item3);
			}
		}
	}

	return buf;
};

// 0xa6 - Channel Scan Request
// Wi-Fi EasyMesh
encoder[0xa6] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.radios) != "array" || length(tlv.radios) > 0xff)
		return null;

	buf.put('B', 0
		| (tlv.perform_fresh_scan << 7)
	);

	buf.put('B', length(tlv.radios));

	for (let item in tlv.radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (type(item.opclass) != "array" || length(item.opclass) > 0xff)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', length(item.opclass));

		for (let item2 in item.opclass) {
			if (type(item2) != "object")
				return null;

			if (type(item2.channels) != "array")
				return null;

			buf.put('B', item2.opclass);
			buf.put('B', length(item2.channels));

			for (let item3 in item2.channels) {
				if (type(item3) != "int" || item3 < 0 || item3 > 0xff)
					return null;

				buf.put('B', item3);
			}
		}
	}

	return buf;
};

// 0xa7 - Channel Scan Result
// Wi-Fi EasyMesh
encoder[0xa7] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (!(tlv.scan_status in [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 ]))
		return null;

	if (type(tlv.timestamp) != "string" || length(tlv.timestamp) > 0xff)
		return null;

	if (type(tlv.neighbors) != "array" || length(tlv.neighbors) > 0xffff)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', tlv.opclass);
	buf.put('B', tlv.channel);
	buf.put('B', tlv.scan_status);
	buf.put('B', length(tlv.timestamp));
	buf.put('*', tlv.timestamp);
	buf.put('B', tlv.utilization);
	buf.put('B', tlv.noise);
	buf.put('!H', length(tlv.neighbors));

	for (let item in tlv.neighbors) {
		if (type(item) != "object")
			return null;

		const bssid = hexdec(match(item.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (bssid == null)
			return null;

		if (type(item.ssid) != "string" || length(item.ssid) > 0xff)
			return null;

		if (type(item.channel_bandwidth) != "string" || length(item.channel_bandwidth) > 0xff)
			return null;

		if (type(item.bss_color) != "int" || item.bss_color < 0 || item.bss_color > 0)
			return null;

		buf.put('6s', bssid);
		buf.put('B', length(item.ssid));
		buf.put('*', item.ssid);
		buf.put('B', item.signal_strength);
		buf.put('B', length(item.channel_bandwidth));
		buf.put('*', item.channel_bandwidth);
		buf.put('B', 0
			| (item.bss_load_element_present << 7)
			| ((item.bss_color & 0b00111111) << 0)
		);

		buf.put('B', item.channel_utilization);
		buf.put('!H', item.station_count);
	}

	buf.put('!L', tlv.aggregate_scan_duration);
	buf.put('B', 0
		| (tlv.scan_type << 7)
	);

	return buf;
};

// 0xa8 - Timestamp
// Wi-Fi EasyMesh
encoder[0xa8] = (buf, timestamp) => {
	if (type(timestamp) != "string" || length(timestamp) > 0xff)
		return null;

	buf.put('B', length(timestamp));
	buf.put('*', timestamp);

	return buf;
};

// 0xa9 - 1905 Layer Security Capability
// Wi-Fi EasyMesh
encoder[0xa9] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	buf.put('B', tlv.onboarding_protocol);
	buf.put('B', tlv.mic_algorithm);
	buf.put('B', tlv.encryption_algorithm);

	return buf;
};

// 0xaa - AP Wi-Fi 6 Capabilities
// Wi-Fi EasyMesh
encoder[0xaa] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.roles) != "array" || length(tlv.roles) > 0xff)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', length(tlv.roles));

	for (let item in tlv.roles) {
		if (type(item) != "object")
			return null;

		if (type(item.agent_role) != "int" || item.agent_role < 0 || item.agent_role > 0b00000011)
			return null;

		if (type(item.mcs_nss) != "string" || length(item.mcs_nss) > 16)
			return null;

		if (type(item.max_dl_mu_mimo_tx) != "int" || item.max_dl_mu_mimo_tx < 0 || item.max_dl_mu_mimo_tx > 0b00001111)
			return null;

		if (type(item.max_ul_mu_mimo_rx) != "int" || item.max_ul_mu_mimo_rx < 0 || item.max_ul_mu_mimo_rx > 0b00001111)
			return null;

		buf.put('B', 0
			| ((item.agent_role & 0b00000011) << 6)
			| (item.he_160 << 5)
			| (item.he_8080 << 4)
			| ((length(item.mcs_nss) & 0b00001111) << 0)
		);

		buf.put('*', item.mcs_nss);
		buf.put('B', 0
			| (item.su_beamformer << 7)
			| (item.su_beamformee << 6)
			| (item.mu_beamformer_status << 5)
			| (item.beamformee_sts_less_80 << 4)
			| (item.beamformee_sts_greater_80 << 3)
			| (item.ul_mu_mimo << 2)
			| (item.ul_ofdma << 1)
			| (item.dl_ofdma << 0)
		);

		buf.put('B', 0
			| ((item.max_dl_mu_mimo_tx & 0b00001111) << 4)
			| ((item.max_ul_mu_mimo_rx & 0b00001111) << 0)
		);

		buf.put('B', item.max_dl_ofdma_tx);
		buf.put('B', item.max_ul_ofdma_rx);
		buf.put('B', 0
			| (item.rts << 7)
			| (item.mu_rts << 6)
			| (item.multi_bssid << 5)
			| (item.mu_edca << 4)
			| (item.twt_requester << 3)
			| (item.twt_responder << 2)
			| (item.spatial_reuse << 1)
			| (item.anticipated_channel_usage << 0)
		);
	}

	return buf;
};

// 0xab - MIC
// Wi-Fi EasyMesh
encoder[0xab] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.gtk_key_id) != "int" || tlv.gtk_key_id < 0 || tlv.gtk_key_id > 0b00000011)
		return null;

	if (type(tlv.mic_version) != "int" || tlv.mic_version < 0 || tlv.mic_version > 0b00000011)
		return null;

	if (type(tlv.integrity_transmission_counter) != "string" || length(tlv.integrity_transmission_counter) > 6)
		return null;

	const source_1905_al_mac_address = hexdec(match(tlv.source_1905_al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (source_1905_al_mac_address == null)
		return null;

	if (type(tlv.mic) != "string" || length(tlv.mic) > 0xffff)
		return null;

	buf.put('B', 0
		| ((tlv.gtk_key_id & 0b00000011) << 6)
		| ((tlv.mic_version & 0b00000011) << 4)
	);

	buf.put('6s', tlv.integrity_transmission_counter);
	buf.put('6s', source_1905_al_mac_address);
	buf.put('!H', length(tlv.mic));
	buf.put('*', tlv.mic);

	return buf;
};

// 0xac - Encrypted
// Wi-Fi EasyMesh
encoder[0xac] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.encryption_transmission_counter) != "string" || length(tlv.encryption_transmission_counter) > 6)
		return null;

	const source_1905_al_mac_address = hexdec(match(tlv.source_1905_al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (source_1905_al_mac_address == null)
		return null;

	const destination_1905_al_mac_address = hexdec(match(tlv.destination_1905_al_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (destination_1905_al_mac_address == null)
		return null;

	if (type(tlv.aes_siv) != "string" || length(tlv.aes_siv) > 0xffff)
		return null;

	buf.put('6s', tlv.encryption_transmission_counter);
	buf.put('6s', source_1905_al_mac_address);
	buf.put('6s', destination_1905_al_mac_address);
	buf.put('!H', length(tlv.aes_siv));
	buf.put('*', tlv.aes_siv);

	return buf;
};

// 0xad - CAC Request
// Wi-Fi EasyMesh
encoder[0xad] = (buf, radios) => {
	if (type(radios) != "array" || length(radios) > 0xff)
		return null;

	buf.put('B', length(radios));

	for (let item in radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (type(item.cac_method) != "int" || item.cac_method < 0 || item.cac_method > 0b00000111)
			return null;

		if (type(item.cac_completion_action) != "int" || item.cac_completion_action < 0 || item.cac_completion_action > 0b00000011)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', item.opclass);
		buf.put('B', item.channel);
		buf.put('B', 0
			| ((item.cac_method & 0b00000111) << 5)
			| ((item.cac_completion_action & 0b00000011) << 3)
		);
	}

	return buf;
};

// 0xae - CAC Termination
// Wi-Fi EasyMesh
encoder[0xae] = (buf, radios) => {
	if (type(radios) != "array" || length(radios) > 0xff)
		return null;

	buf.put('B', length(radios));

	for (let item in radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', item.opclass);
		buf.put('B', item.channel);
	}

	return buf;
};

// 0xaf - CAC Completion Report
// Wi-Fi EasyMesh
encoder[0xaf] = (buf, radios) => {
	if (type(radios) != "array" || length(radios) > 0xff)
		return null;

	buf.put('B', length(radios));

	for (let item in radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (!(item.cac_completion_status in [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 ]))
			return null;

		if (type(item.pairs) != "array" || length(item.pairs) > 0xff)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', item.opclass);
		buf.put('B', item.channel);
		buf.put('B', item.cac_completion_status);
		buf.put('B', length(item.pairs));

		for (let item2 in item.pairs) {
			if (type(item2) != "object")
				return null;

			buf.put('B', item2.opclass_detected);
			buf.put('B', item2.channel_detected);
		}
	}

	return buf;
};

// 0xb0 - Associated Wi-Fi 6 STA Status Report
// Wi-Fi EasyMesh
encoder[0xb0] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	if (type(tlv.n2) != "array" || length(tlv.n2) > 0xff)
		return null;

	buf.put('6s', mac_address);
	buf.put('B', length(tlv.n2));

	for (let item in tlv.n2) {
		if (type(item) != "object")
			return null;

		buf.put('B', item.tid);
		buf.put('B', item.queue_size);
	}

	return buf;
};

// 0xb1 - CAC Status Report
// Wi-Fi EasyMesh
encoder[0xb1] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.available_channels) != "array" || length(tlv.available_channels) > 0xff)
		return null;

	if (type(tlv.radar_detected_channels) != "array" || length(tlv.radar_detected_channels) > 0xff)
		return null;

	if (type(tlv.active_cac_channels) != "array" || length(tlv.active_cac_channels) > 0xff)
		return null;

	buf.put('B', length(tlv.available_channels));

	for (let item in tlv.available_channels) {
		if (type(item) != "object")
			return null;

		buf.put('B', item.opclass);
		buf.put('B', item.channel);
		buf.put('!H', item.minutes);
	}

	buf.put('B', length(tlv.radar_detected_channels));

	for (let item in tlv.radar_detected_channels) {
		if (type(item) != "object")
			return null;

		buf.put('B', item.opclass);
		buf.put('B', item.channel);
		buf.put('!H', item.duration);
	}

	buf.put('B', length(tlv.active_cac_channels));

	for (let item in tlv.active_cac_channels) {
		if (type(item) != "object")
			return null;

		if (type(item.countdown) != "string" || length(item.countdown) > 3)
			return null;

		buf.put('B', item.opclass);
		buf.put('B', item.channel);
		buf.put('3s', item.countdown);
	}

	return buf;
};

// 0xb2 - CAC Capabilities
// Wi-Fi EasyMesh
encoder[0xb2] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.country_code) != "string" || length(tlv.country_code) > 2)
		return null;

	if (type(tlv.radios) != "array" || length(tlv.radios) > 0xff)
		return null;

	buf.put('2s', tlv.country_code);
	buf.put('B', length(tlv.radios));

	for (let item in tlv.radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (type(item.cac_types_supported) != "array" || length(item.cac_types_supported) > 0xff)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', length(item.cac_types_supported));

		for (let item2 in item.cac_types_supported) {
			if (type(item2) != "object")
				return null;

			if (!(item2.cac_method_supported in [ 0x00, 0x01, 0x02, 0x03 ]))
				return null;

			if (type(item2.duration) != "string" || length(item2.duration) > 3)
				return null;

			if (type(item2.opclasses) != "array" || length(item2.opclasses) > 0xff)
				return null;

			buf.put('B', item2.cac_method_supported);
			buf.put('3s', item2.duration);
			buf.put('B', length(item2.opclasses));

			for (let item3 in item2.opclasses) {
				if (type(item3) != "object")
					return null;

				if (type(item3.channels) != "array" || length(item3.channels) > 0xff)
					return null;

				buf.put('B', item3.opclass);
				buf.put('B', length(item3.channels));

				for (let channel in item3.channels) {
					buf.put('B', channel);
				}
			}
		}
	}

	return buf;
};

// 0xb3 - Multi-AP Profile
// Wi-Fi EasyMesh
encoder[0xb3] = (buf, profile) => {
	if (!(profile in [ 0x00, 0x01, 0x02, 0x03 ]))
		return null;

	buf.put('B', profile);

	return buf;
};

// 0xb4 - Profile-2 AP Capability
// Wi-Fi EasyMesh
encoder[0xb4] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (!(tlv.byte_counter_unit in [ 0x0, 0x1, 0x2 ]))
		return null;

	buf.put('B', tlv.max_prioritization_rules);
	buf.put('B', 0
		| ((tlv.byte_counter_unit & 0b00000011) << 6)
		| (tlv.supports_prioritization << 5)
		| (tlv.supports_dpp_onboarding << 4)
		| (tlv.supports_traffic_separation << 3)
	);

	buf.put('B', tlv.max_unique_vids);

	return buf;
};

// 0xb5 - Default 802.1Q Settings
// Wi-Fi EasyMesh
encoder[0xb5] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.default_pcp) != "int" || tlv.default_pcp < 0 || tlv.default_pcp > 0b00000111)
		return null;

	buf.put('!H', tlv.primary_vlan_id);
	buf.put('B', 0
		| ((tlv.default_pcp & 0b00000111) << 5)
	);

	return buf;
};

// 0xb6 - Traffic Separation Policy
// Wi-Fi EasyMesh
encoder[0xb6] = (buf, ssids) => {
	if (type(ssids) != "array" || length(ssids) > 0xff)
		return null;

	buf.put('B', length(ssids));

	for (let item in ssids) {
		if (type(item) != "object")
			return null;

		if (type(item.ssid_name) != "string" || length(item.ssid_name) > 0xff)
			return null;

		buf.put('B', length(item.ssid_name));
		buf.put('*', item.ssid_name);
		buf.put('!H', item.vlan_id);
	}

	return buf;
};

// 0xb7 - BSS Configuration Report TLV format BSSID
// Wi-Fi EasyMesh
encoder[0xb7] = (buf, radios) => {
	if (type(radios) != "array" || length(radios) > 0xff)
		return null;

	buf.put('B', length(radios));

	for (let item in radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (type(item.bss) != "array" || length(item.bss) > 0xff)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', length(item.bss));

		for (let item2 in item.bss) {
			if (type(item2) != "object")
				return null;

			const bssid = hexdec(match(item2.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

			if (bssid == null)
				return null;

			if (type(item2.ssid) != "string" || length(item2.ssid) > 0xff)
				return null;

			buf.put('6s', bssid);
			buf.put('B', 0
				| (item2.backhaul << 7)
				| (item2.fronthaul << 6)
				| (item2.r1_disallowed_status << 5)
				| (item2.r2_disallowed_status << 4)
				| (item2.multiple_bssid << 3)
				| (item2.transmitted_bssid << 2)
			);

			buf.put('B', length(item2.ssid));
			buf.put('*', item2.ssid);
		}
	}

	return buf;
};

// 0xb8 - BSSID
// Wi-Fi EasyMesh
encoder[0xb8] = (buf, bssid) => {
	const _bssid = hexdec(match(bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (_bssid == null)
		return null;

	buf.put('6s', _bssid);

	return buf;
};

// 0xb9 - Service Prioritization Rule
// Wi-Fi EasyMesh
encoder[0xb9] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	buf.put('!L', tlv.rule_id);
	buf.put('B', 0
		| (tlv.add_remove << 7)
	);

	buf.put('B', tlv.precedence);
	buf.put('B', tlv.output);
	buf.put('B', 0
		| (tlv.always_match << 7)
	);

	return buf;
};

// 0xba - DSCP Mapping Table
// Wi-Fi EasyMesh
encoder[0xba] = (buf, dscp_pcp_mapping) => {
	if (type(dscp_pcp_mapping) != "array")
		return null;

	for (let pcp_value in dscp_pcp_mapping) {
		buf.put('B', pcp_value);
	}

	return buf;
};

// 0xbb - BSS Configuration Request
// Wi-Fi EasyMesh
encoder[0xbb] = (buf, payload) => buf.put('*', payload),

// 0xbc - Profile-2 Error Code
// Wi-Fi EasyMesh
encoder[0xbc] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (!(tlv.reason_code in [ 0x01, 0x02, 0x03, 0x05, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D ]))
		return null;

	let bssid = null;

	if (tlv.bssid != null) {
		bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (bssid == null)
			return null;
	}

	buf.put('B', tlv.reason_code);

	if (bssid != null) {
		if (tlv.reason_code == null)
			tlv.reason_code = 7;

		if (bssid != null)
			buf.put('6s', bssid);
	}

	if (tlv.service_prio_rule_id != null) {
		if (tlv.reason_code == null)
			tlv.reason_code = 1;

		buf.put('!L', tlv.service_prio_rule_id);
	}

	if (tlv.qmid != null) {
		if (tlv.reason_code == null)
			tlv.reason_code = 11;

		buf.put('!H', tlv.qmid);
	}

	return buf;
};

// 0xbd - BSS Configuration Response
// Wi-Fi EasyMesh
encoder[0xbd] = (buf, payload) => buf.put('*', payload),

// 0xbe - AP Radio Advanced Capabilities
// Wi-Fi EasyMesh
encoder[0xbe] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', 0
		| (tlv.combined_front_back << 7)
		| (tlv.combined_profile1_profile2 << 6)
		| (tlv.mscs << 5)
		| (tlv.scs << 4)
		| (tlv.qos_map << 3)
		| (tlv.dscp_policy << 2)
	);

	return buf;
};

// 0xbf - Association Status Notification
// Wi-Fi EasyMesh
encoder[0xbf] = (buf, bssids) => {
	if (type(bssids) != "array" || length(bssids) > 0xff)
		return null;

	buf.put('B', length(bssids));

	for (let item in bssids) {
		if (type(item) != "object")
			return null;

		const bssid = hexdec(match(item.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (bssid == null)
			return null;

		if (!(item.association_allowance_status in [ 0x00, 0x01 ]))
			return null;

		buf.put('6s', bssid);
		buf.put('B', item.association_allowance_status);
	}

	return buf;
};

// 0xc0 - Source Info
// Wi-Fi EasyMesh
encoder[0xc0] = (buf, mac_address) => {
	const _mac_address = hexdec(match(mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (_mac_address == null)
		return null;

	buf.put('6s', _mac_address);

	return buf;
};

// 0xc1 - Tunneled message type
// Wi-Fi EasyMesh
encoder[0xc1] = (buf, tunneled_protocol_type) => {
	if (!(tunneled_protocol_type in [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 ]))
		return null;

	buf.put('B', tunneled_protocol_type);

	return buf;
};

// 0xc2 - Tunneled
// Wi-Fi EasyMesh
encoder[0xc2] = (buf, payload) => buf.put('*', payload),

// 0xc3 - Profile-2 Steering Request
// Wi-Fi EasyMesh
encoder[0xc3] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	if (type(tlv.sta_list) != "array" || length(tlv.sta_list) > 0xff)
		return null;

	if (type(tlv.target_bssids) != "array" || length(tlv.target_bssids) > 0xff)
		return null;

	buf.put('6s', bssid);
	buf.put('B', 0
		| (tlv.request_mode << 7)
		| (tlv.btm_disassociation_imminent_bit << 6)
		| (tlv.btm_abridged_bit << 5)
	);

	buf.put('!H', tlv.steering_opportunity_window);
	buf.put('!H', tlv.btm_disassociation_timer);
	buf.put('B', length(tlv.sta_list));

	for (let mac_address in tlv.sta_list) {
		const _mac_address = hexdec(match(mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_mac_address == null)
			return null;

		buf.put('6s', _mac_address);
	}

	buf.put('B', length(tlv.target_bssids));

	for (let item in tlv.target_bssids) {
		if (type(item) != "object")
			return null;

		const target_bssid = hexdec(match(item.target_bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (target_bssid == null)
			return null;

		buf.put('6s', target_bssid);
		buf.put('B', item.target_bss_opclass);
		buf.put('B', item.target_bss_channel);
		buf.put('B', item.reason_code);
	}

	return buf;
};

// 0xc4 - Unsuccessful Association Policy
// Wi-Fi EasyMesh
encoder[0xc4] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	buf.put('B', 0
		| (tlv.report_unsuccessful_assocs << 7)
	);

	buf.put('!L', tlv.max_reporting_rate);

	return buf;
};

// 0xc5 - Metric Collection Interval
// Wi-Fi EasyMesh
encoder[0xc5] = (buf, collection_interval) => {

	buf.put('!L', collection_interval);

	return buf;
};

// 0xc6 - Radio Metrics
// Wi-Fi EasyMesh
encoder[0xc6] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', tlv.noise);
	buf.put('B', tlv.transmit);
	buf.put('B', tlv.receive_self);
	buf.put('B', tlv.receive_other);

	return buf;
};

// 0xc7 - AP Extended Metrics
// Wi-Fi EasyMesh
encoder[0xc7] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	buf.put('6s', bssid);
	buf.put('!L', tlv.unicast_bytes_sent);
	buf.put('!L', tlv.unicast_bytes_received);
	buf.put('!L', tlv.multicast_bytes_sent);
	buf.put('!L', tlv.multicast_bytes_received);
	buf.put('!L', tlv.broadcast_bytes_sent);
	buf.put('!L', tlv.broadcast_bytes_received);

	return buf;
};

// 0xc8 - Associated STA Extended Link Metrics
// Wi-Fi EasyMesh
encoder[0xc8] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	if (type(tlv.bssids) != "array" || length(tlv.bssids) > 0xff)
		return null;

	buf.put('6s', mac_address);
	buf.put('B', length(tlv.bssids));

	for (let item in tlv.bssids) {
		if (type(item) != "object")
			return null;

		const bssid = hexdec(match(item.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (bssid == null)
			return null;

		buf.put('6s', bssid);
		buf.put('!L', item.last_data_downlink_rate);
		buf.put('!L', item.last_data_uplink_rate);
		buf.put('!L', item.utilization_receive);
		buf.put('!L', item.utilization_transmit);
	}

	return buf;
};

// 0xc9 - Status Code
// Wi-Fi EasyMesh
encoder[0xc9] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	buf.put('!H', tlv.octets_count);
	buf.put('!H', tlv.status_code);

	return buf;
};

// 0xca - Reason Code
// Wi-Fi EasyMesh
encoder[0xca] = (buf, reason_code) => {

	buf.put('!H', reason_code);

	return buf;
};

// 0xcb - Backhaul STA Radio Capabilities
// Wi-Fi EasyMesh
encoder[0xcb] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	const mac_address_included = hexdec(match(tlv.mac_address_included, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address_included == null)
		return null;

	const mac_address = hexdec(match(tlv.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (mac_address == null)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', 0
		| (tlv.mac_address_included << 7)
	);

	buf.put('6s', mac_address);

	return buf;
};

// 0xcc - AKM Suite Capabilities
// Wi-Fi EasyMesh
encoder[0xcc] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.backhaul_akm_suite_selectors) != "array" || length(tlv.backhaul_akm_suite_selectors) > 0xff)
		return null;

	if (type(tlv.fronthaul_akm_suite_selectors) != "array" || length(tlv.fronthaul_akm_suite_selectors) > 0xff)
		return null;

	buf.put('B', length(tlv.backhaul_akm_suite_selectors));

	for (let item in tlv.backhaul_akm_suite_selectors) {
		if (type(item) != "object")
			return null;

		if (type(item.bh_oui) != "string" || length(item.bh_oui) > 3)
			return null;

		buf.put('3s', item.bh_oui);
		buf.put('B', item.bh_akm_suite_type);
	}

	buf.put('B', length(tlv.fronthaul_akm_suite_selectors));

	for (let item in tlv.fronthaul_akm_suite_selectors) {
		if (type(item) != "object")
			return null;

		if (type(item.fh_oui) != "string" || length(item.fh_oui) > 3)
			return null;

		buf.put('3s', item.fh_oui);
		buf.put('B', item.fh_akm_suite_type);
	}

	return buf;
};

// 0xcd - 1905 Encap DPP
// Wi-Fi EasyMesh
encoder[0xcd] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const enrollee_mac_address_present = hexdec(match(tlv.enrollee_mac_address_present, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (enrollee_mac_address_present == null)
		return null;

	const destination_sta_mac_address = hexdec(match(tlv.destination_sta_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (destination_sta_mac_address == null)
		return null;

	if (type(tlv.encapsulated_frame) != "string" || length(tlv.encapsulated_frame) > 0xffff)
		return null;

	buf.put('B', 0
		| (tlv.enrollee_mac_address_present << 7)
		| (tlv.dpp_frame_indicator << 5)
	);

	buf.put('6s', destination_sta_mac_address);
	buf.put('B', tlv.frame_type);
	buf.put('!H', length(tlv.encapsulated_frame));
	buf.put('*', tlv.encapsulated_frame);

	return buf;
};

// 0xce - 1905 Encap EAPOL
// Wi-Fi EasyMesh
encoder[0xce] = (buf, payload) => buf.put('*', payload),

// 0xcf - DPP Bootstrapping URI Notification
// Wi-Fi EasyMesh
encoder[0xcf] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	const backhaul_sta_address = hexdec(match(tlv.backhaul_sta_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (backhaul_sta_address == null)
		return null;

	if (type(tlv.dpp_uri) != "string")
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('6s', bssid);
	buf.put('6s', backhaul_sta_address);
	buf.put('*', tlv.dpp_uri);

	return buf;
};

// 0xd0 - Backhaul BSS Configuration
// Wi-Fi EasyMesh
encoder[0xd0] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	buf.put('6s', bssid);
	buf.put('B', 0
		| (tlv.profile1_backhaul_sta_disallowed << 7)
		| (tlv.profile2_backhaul_sta_disallowed << 6)
	);

	return buf;
};

// 0xd1 - DPP Message
// Wi-Fi EasyMesh
encoder[0xd1] = (buf, payload) => buf.put('*', payload),

// 0xd2 - DPP CCE Indication
// Wi-Fi EasyMesh
encoder[0xd2] = (buf, advertise_cce) => {
	if (!(advertise_cce in [ 0, 1 ]))
		return null;

	buf.put('B', advertise_cce);

	return buf;
};

// 0xd3 - DPP Chirp Value
// Wi-Fi EasyMesh
encoder[0xd3] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const enrollee_mac_address_present = hexdec(match(tlv.enrollee_mac_address_present, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (enrollee_mac_address_present == null)
		return null;

	const destination_sta_mac_address = hexdec(match(tlv.destination_sta_mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (destination_sta_mac_address == null)
		return null;

	if (type(tlv.hash_value) != "string" || length(tlv.hash_value) > 0xff)
		return null;

	buf.put('B', 0
		| (tlv.enrollee_mac_address_present << 7)
		| (tlv.hash_validity << 6)
	);

	buf.put('6s', destination_sta_mac_address);
	buf.put('B', length(tlv.hash_value));
	buf.put('*', tlv.hash_value);

	return buf;
};

// 0xd4 - Device Inventory
// Wi-Fi EasyMesh
encoder[0xd4] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.serial_number) != "string" || length(tlv.serial_number) > 0xff)
		return null;

	if (type(tlv.software_version) != "string" || length(tlv.software_version) > 0xff)
		return null;

	if (type(tlv.execution_env) != "string" || length(tlv.execution_env) > 0xff)
		return null;

	if (type(tlv.radios) != "array" || length(tlv.radios) > 0xff)
		return null;

	buf.put('B', length(tlv.serial_number));
	buf.put('*', tlv.serial_number);
	buf.put('B', length(tlv.software_version));
	buf.put('*', tlv.software_version);
	buf.put('B', length(tlv.execution_env));
	buf.put('*', tlv.execution_env);
	buf.put('B', length(tlv.radios));

	for (let item in tlv.radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (type(item.chipset_vendor) != "string" || length(item.chipset_vendor) > 0xff)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', length(item.chipset_vendor));
		buf.put('*', item.chipset_vendor);
	}

	return buf;
};

// 0xd5 - Agent List
// Wi-Fi EasyMesh
encoder[0xd5] = (buf, multi_ap_agents_present) => {
	if (type(multi_ap_agents_present) != "array" || length(multi_ap_agents_present) > 0xff)
		return null;

	buf.put('B', length(multi_ap_agents_present));

	for (let item in multi_ap_agents_present) {
		if (type(item) != "object")
			return null;

		const mac_address = hexdec(match(item.mac_address, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (mac_address == null)
			return null;

		if (!(item.multi_ap_profile in [ 0x01, 0x02, 0x03 ]))
			return null;

		if (type(item.security) != "int" || item.security < 0 || item.security > 255)
			return null;

		buf.put('6s', mac_address);
		buf.put('B', item.multi_ap_profile);
		buf.put('B', item.security);
	}

	return buf;
};

// 0xd6 - Anticipated Channel Preference
// Wi-Fi EasyMesh
encoder[0xd6] = (buf, opclasses) => {
	if (type(opclasses) != "array" || length(opclasses) > 0xff)
		return null;

	buf.put('B', length(opclasses));

	for (let item in opclasses) {
		if (type(item) != "object")
			return null;

		if (type(item.channels) != "array")
			return null;

		buf.put('B', item.opclass);
		buf.put('B', length(item.channels));

		for (let item2 in item.channels) {
			if (type(item2) != "int" || item2 < 0 || item2 > 0xff)
				return null;

			buf.put('B', item2);
		}
	}

	return buf;
};

// 0xd7 - Anticipated Channel Usage
// Wi-Fi EasyMesh
encoder[0xd7] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const reference_bssid = hexdec(match(tlv.reference_bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (reference_bssid == null)
		return null;

	if (type(tlv.usage_entries) != "array" || length(tlv.usage_entries) > 0xff)
		return null;

	buf.put('B', tlv.opclass);
	buf.put('B', tlv.channel);
	buf.put('6s', reference_bssid);
	buf.put('B', length(tlv.usage_entries));
	buf.put('!L', tlv.burst_start_time);

	for (let item in tlv.usage_entries) {
		if (type(item) != "object")
			return null;

		if (type(item.ru_bitmask) != "string" || length(item.ru_bitmask) > 0xff)
			return null;

		const transmitter_identifier = hexdec(match(item.transmitter_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (transmitter_identifier == null)
			return null;

		buf.put('!L', item.burst_length);
		buf.put('!L', item.repetitions_count);
		buf.put('!L', item.burst_interval);
		buf.put('B', length(item.ru_bitmask));
		buf.put('*', item.ru_bitmask);
		buf.put('6s', transmitter_identifier);
		buf.put('B', item.power_level);
		buf.put('B', item.channel_usage_reason);
	}

	return buf;
};

// 0xd8 - Spatial Reuse Request
// Wi-Fi EasyMesh
encoder[0xd8] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.bss_color) != "int" || tlv.bss_color < 0 || tlv.bss_color > 0b00111111)
		return null;

	const srg_partial_bssid_bitmap = hexdec(match(tlv.srg_partial_bssid_bitmap, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (srg_partial_bssid_bitmap == null)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', 0
		| ((tlv.bss_color & 0b00111111) << 0)
	);

	buf.put('B', 0
		| (tlv.hesiga_spatial_reuse_value15_allowed << 4)
		| (tlv.srg_information_valid << 3)
		| (tlv.non_srg_offset_valid << 2)
		| (tlv.psr_disallowed << 0)
	);

	buf.put('B', tlv.non_srg_obsspd_max_offset);
	buf.put('B', tlv.srg_obsspd_min_offset);
	buf.put('B', tlv.srg_obsspd_max_offset);
	buf.put('!Q', tlv.srg_bss_color_bitmap);
	buf.put('6s', srg_partial_bssid_bitmap);

	return buf;
};

// 0xd9 - Spatial Reuse Report
// Wi-Fi EasyMesh
encoder[0xd9] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.bss_color) != "int" || tlv.bss_color < 0 || tlv.bss_color > 0b00111111)
		return null;

	const srg_partial_bssid_bitmap = hexdec(match(tlv.srg_partial_bssid_bitmap, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (srg_partial_bssid_bitmap == null)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', 0
		| (tlv.partial_bss_color << 6)
		| ((tlv.bss_color & 0b00111111) << 0)
	);

	buf.put('B', 0
		| (tlv.hesiga_spatial_reuse_value15_allowed << 4)
		| (tlv.srg_information_valid << 3)
		| (tlv.non_srg_offset_valid << 2)
		| (tlv.psr_disallowed << 0)
	);

	buf.put('B', tlv.non_srg_obsspd_max_offset);
	buf.put('B', tlv.srg_obsspd_min_offset);
	buf.put('B', tlv.srg_obsspd_max_offset);
	buf.put('!Q', tlv.srg_bss_color_bitmap);
	buf.put('6s', srg_partial_bssid_bitmap);
	buf.put('!Q', tlv.used_neighbor_bss_colors);

	return buf;
};

// 0xda - Spatial Reuse Config Response
// Wi-Fi EasyMesh
encoder[0xda] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (!(tlv.response_code in [ 0x00, 0x01 ]))
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', tlv.response_code);

	return buf;
};

// 0xdb - QoS Management Policy
// Wi-Fi EasyMesh
encoder[0xdb] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.mscs_disallowed_sta) != "array" || length(tlv.mscs_disallowed_sta) > 0xff)
		return null;

	if (type(tlv.scs_disallowed_sta) != "array" || length(tlv.scs_disallowed_sta) > 0xff)
		return null;

	buf.put('B', length(tlv.mscs_disallowed_sta));

	for (let mscs_disallowed_sta_mac in tlv.mscs_disallowed_sta) {
		const _mscs_disallowed_sta_mac = hexdec(match(mscs_disallowed_sta_mac, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_mscs_disallowed_sta_mac == null)
			return null;

		buf.put('6s', _mscs_disallowed_sta_mac);
	}

	buf.put('B', length(tlv.scs_disallowed_sta));

	for (let scs_disallowed_sta_mac in tlv.scs_disallowed_sta) {
		const _scs_disallowed_sta_mac = hexdec(match(scs_disallowed_sta_mac, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (_scs_disallowed_sta_mac == null)
			return null;

		buf.put('6s', _scs_disallowed_sta_mac);
	}

	return buf;
};

// 0xdc - QoS Management Descriptor
// Wi-Fi EasyMesh
encoder[0xdc] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	const client_mac = hexdec(match(tlv.client_mac, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (client_mac == null)
		return null;

	if (type(tlv.descriptor_element) != "string")
		return null;

	buf.put('!H', tlv.qmid);
	buf.put('6s', bssid);
	buf.put('6s', client_mac);
	buf.put('*', tlv.descriptor_element);

	return buf;
};

// 0xdd - Controller Capability
// Wi-Fi EasyMesh
encoder[0xdd] = (buf, ki_bmi_b_counter) => {

	buf.put('B', 0
		| (ki_bmi_b_counter << 7)
	);

	return buf;
};

// -----------------------------------------------------------------------------
// TLV DECODER ROUTINES
// -----------------------------------------------------------------------------

export const decoder = [];

// 0x00 - End of message
// IEEE1905.1-2013
decoder[0x00] = (buf, end) => '',

// 0x01 - 1905.1 AL MAC address
// IEEE1905.1-2013
decoder[0x01] = (buf, end) => {
	if (buf.pos() + 6 > end)
		return null;

	const al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return al_mac_address;
};

// 0x02 - MAC address
// IEEE1905.1-2013
decoder[0x02] = (buf, end) => {
	if (buf.pos() + 6 > end)
		return null;

	const if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return if_mac_address;
};

// 0x03 - 1905.1 device information
// IEEE1905.1-2013
decoder[0x03] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const local_interfaces_count = buf.get('B');
	const local_interfaces = [];

	for (let h = 0; h < local_interfaces_count; h++) {
		if (buf.pos() + 9 > end)
			return null;

		const local_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const media_type = buf.get('!H');

		if (!exists(defs.MEDIA_TYPE, media_type))
			return null;

		const octets_count = buf.get('B');

		if (buf.pos() + octets_count > end)
			return null;

		const media_specific_information = buf.get(octets_count);

		push(local_interfaces, {
			local_if_mac_address,
			media_type,
			media_type_name: defs.MEDIA_TYPE[media_type],
			media_specific_information,
		});
	}

	return {
		al_mac_address,
		local_interfaces,
	};
};

// 0x04 - Device bridging capability
// IEEE1905.1-2013
decoder[0x04] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const bridging_tuples_count = buf.get('B');
	const bridging_tuples = [];

	for (let h = 0; h < bridging_tuples_count; h++) {
		if (buf.pos() + 1 > end)
			return null;

		const mac_addresses_count = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const mac_addresses = [];

		for (let i = 0; i < mac_addresses_count; i++) {
			if (buf.pos() + 6 > end)
				return null;

			const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

			push(mac_addresses, mac_address);
		}

		push(bridging_tuples, mac_addresses);
	}

	return bridging_tuples;
};

// 0x06 - Non-1905 neighbor devices
// IEEE1905.1-2013
decoder[0x06] = (buf, end) => {
	if (buf.pos() + 6 > end)
		return null;

	const local_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const non_ieee1905_neighbors = [];

	while (buf.pos() + 6 < end) {
		const non_1905_neighbor_device_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(non_ieee1905_neighbors, non_1905_neighbor_device_mac_address);
	}

	return {
		local_if_mac_address,
		non_ieee1905_neighbors,
	};
};

// 0x07 - 1905 neighbor devices
// IEEE1905.1-2013
decoder[0x07] = (buf, end) => {
	if (buf.pos() + 6 > end)
		return null;

	const local_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const ieee1905_neighbors = [];

	while (buf.pos() + 7 < end) {
		const neighbor_al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		const bitfield = buf.get('B');
		const bridges_present = ((bitfield & 0b10000000) == 0b10000000);

		push(ieee1905_neighbors, {
			neighbor_al_mac_address,
			bridges_present,
		});
	}

	return {
		local_if_mac_address,
		ieee1905_neighbors,
	};
};

// 0x08 - Link metric query
// IEEE1905.1-2013
decoder[0x08] = (buf, end) => {
	if (buf.pos() + 2 > end)
		return null;

	const query_type = buf.get('B');

	if (!exists(defs.QUERY_TYPE, query_type))
		return null;

	let al_mac_address = null;

	if (query_type == 1) {
		al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	}

	const link_metrics_requested = buf.get('B');

	if (!exists(defs.LINK_METRICS_REQUESTED, link_metrics_requested))
		return null;

	return {
		query_type,
		query_type_name: defs.QUERY_TYPE[query_type],
		al_mac_address,
		link_metrics_requested,
		link_metrics_requested_name: defs.LINK_METRICS_REQUESTED[link_metrics_requested],
	};
};

// 0x09 - 1905.1 transmitter link metric
// IEEE1905.1-2013
decoder[0x09] = (buf, end) => {
	if (buf.pos() + 12 > end)
		return null;

	const transmitter_al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const neighbor_al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const link_metrics = [];

	while (buf.pos() + 29 < end) {
		const local_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const remote_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const media_type = buf.get('!H');

		if (!exists(defs.MEDIA_TYPE, media_type))
			return null;

		const bridges_present = buf.get('?');
		const packet_errors = buf.get('!L');
		const transmitted_packets = buf.get('!L');
		const mac_throughput_capacity = buf.get('!H');
		const link_availability = buf.get('!H');
		const phy_rate = buf.get('!H');

		push(link_metrics, {
			local_if_mac_address,
			remote_if_mac_address,
			media_type,
			media_type_name: defs.MEDIA_TYPE[media_type],
			bridges_present,
			packet_errors,
			transmitted_packets,
			mac_throughput_capacity,
			link_availability,
			phy_rate,
		});
	}

	return {
		transmitter_al_mac_address,
		neighbor_al_mac_address,
		link_metrics,
	};
};

// 0x0a - 1905.1 receiver link metric
// IEEE1905.1-2013
decoder[0x0a] = (buf, end) => {
	if (buf.pos() + 12 > end)
		return null;

	const transmitter_al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const neighbor_al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const link_metrics = [];

	while (buf.pos() + 23 < end) {
		const local_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const remote_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const media_type = buf.get('!H');

		if (!exists(defs.MEDIA_TYPE, media_type))
			return null;

		const packet_errors = buf.get('!L');
		const received_packets = buf.get('!L');
		const rssi = buf.get('B');

		push(link_metrics, {
			local_if_mac_address,
			remote_if_mac_address,
			media_type,
			media_type_name: defs.MEDIA_TYPE[media_type],
			packet_errors,
			received_packets,
			rssi,
		});
	}

	return {
		transmitter_al_mac_address,
		neighbor_al_mac_address,
		link_metrics,
	};
};

// 0x0b - Vendor specific
// IEEE1905.1-2013
decoder[0x0b] = (buf, end) => {
	if (buf.pos() + 3 > end)
		return null;

	const vendor_specific_oui = buf.get(3);
	const vendor_specific_information = buf.get('*');

	return {
		vendor_specific_oui,
		vendor_specific_information,
	};
};

// 0x0c - 1905.1 link metric result code
// IEEE1905.1-2013
decoder[0x0c] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const result_code = buf.get('B');

	if (!exists(defs.LINK_METRIC_RESULT_CODE, result_code))
		return null;

	return {
		result_code,
		result_code_name: defs.LINK_METRIC_RESULT_CODE[result_code],
	};
};

// 0x0d - Searched Role
// IEEE1905.1-2013
decoder[0x0d] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const role = buf.get('B');

	if (!exists(defs.IEEE1905_ROLE, role))
		return null;

	return {
		role,
		role_name: defs.IEEE1905_ROLE[role],
	};
};

// 0x0e - Autoconfig Frequency Band
// IEEE1905.1-2013
decoder[0x0e] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const frequency_band = buf.get('B');

	return frequency_band;
};

// 0x0f - Supported Role
// IEEE1905.1-2013
decoder[0x0f] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const type_of_role = buf.get('B');

	return type_of_role;
};

// 0x10 - Supported Frequency Band
// IEEE1905.1-2013
decoder[0x10] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const frequency_band = buf.get('B');

	return frequency_band;
};

// 0x11 - WSC
// IEEE1905.1-2013
decoder[0x11] = (buf, end) => buf.get(end - buf.pos()),

// 0x12 - Push_Button_Event notification
// IEEE1905.1-2013
decoder[0x12] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const media_types_count = buf.get('B');
	const media_types = [];

	for (let h = 0; h < media_types_count; h++) {
		if (buf.pos() + 3 > end)
			return null;

		const media_type = buf.get('!H');

		if (!exists(defs.MEDIA_TYPE, media_type))
			return null;

		const octets_count = buf.get('B');

		if (buf.pos() + octets_count > end)
			return null;

		const media_specific_information = buf.get(octets_count);

		push(media_types, {
			media_type,
			media_type_name: defs.MEDIA_TYPE[media_type],
			media_specific_information,
		});
	}

	return media_types;
};

// 0x13 - Push_Button_Join notification
// IEEE1905.1-2013
decoder[0x13] = (buf, end) => {
	if (buf.pos() + 20 > end)
		return null;

	const al_id = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const message_identifier = buf.get('!H');
	const transmitter_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const neighbor_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return {
		al_id,
		message_identifier,
		transmitter_if_mac_address,
		neighbor_if_mac_address,
	};
};

// 0x14 - Generic Phy device information
// IEEE1905.1a-2014
decoder[0x14] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const local_interfaces_count = buf.get('B');
	const local_interfaces = [];

	for (let h = 0; h < local_interfaces_count; h++) {
		if (buf.pos() + 44 > end)
			return null;

		const local_if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const phy_oui = buf.get(3);
		const phy_variant = buf.get('B');
		const phy_variant_name = buf.get(32);
		const phy_description_url_length = buf.get('B');
		const media_specific_information_length = buf.get('B');

		if (buf.pos() + phy_description_url_length > end)
			return null;

		const phy_description_url = buf.get(phy_description_url_length);

		if (buf.pos() + media_specific_information_length > end)
			return null;

		const media_specific_information = buf.get(media_specific_information_length);

		push(local_interfaces, {
			local_if_mac_address,
			phy_oui,
			phy_variant,
			phy_variant_name,
			phy_description_url,
			media_specific_information,
		});
	}

	return {
		al_mac_address,
		local_interfaces,
	};
};

// 0x15 - Device identification
// IEEE1905.1a-2014
decoder[0x15] = (buf, end) => {
	if (buf.pos() + 192 > end)
		return null;

	const friendly_name = buf.get(64);
	const manufacturer_name = buf.get(64);
	const manufacturer_model = buf.get(64);

	return {
		friendly_name,
		manufacturer_name,
		manufacturer_model,
	};
};

// 0x16 - Control URL
// IEEE1905.1a-2014
decoder[0x16] = (buf, end) => buf.get(end - buf.pos()),

// 0x17 - IPv4
// IEEE1905.1a-2014
decoder[0x17] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const num_interfaces = buf.get('B');
	const interfaces = [];

	for (let h = 0; h < num_interfaces; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const addresses_count = buf.get('B');

		if (addresses_count > 0x0f)
			return null;

		const addresses = [];

		for (let i = 0; i < addresses_count; i++) {
			if (buf.pos() + 9 > end)
				return null;

			const ipv4addr_type = buf.get('B');

			if (!exists(defs.IPV4ADDR_TYPE, ipv4addr_type))
				return null;

			const address = arrtoip(buf.read('4B'));
			const dhcp_server = arrtoip(buf.read('4B'));

			push(addresses, {
				ipv4addr_type,
				ipv4addr_type_name: defs.IPV4ADDR_TYPE[ipv4addr_type],
				address,
				dhcp_server,
			});
		}

		push(interfaces, {
			if_mac_address,
			addresses,
		});
	}

	return interfaces;
};

// 0x18 - IPv6
// IEEE1905.1a-2014
decoder[0x18] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const num_interfaces = buf.get('B');
	const interfaces = [];

	for (let h = 0; h < num_interfaces; h++) {
		if (buf.pos() + 23 > end)
			return null;

		const if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const linklocal_address = arrtoip(buf.read('16B'));
		const other_addresses_count = buf.get('B');

		if (other_addresses_count > 0x0f)
			return null;

		const other_addresses = [];

		for (let i = 0; i < other_addresses_count; i++) {
			if (buf.pos() + 33 > end)
				return null;

			const ipv6addr_type = buf.get('B');

			if (!exists(defs.IPV6ADDR_TYPE, ipv6addr_type))
				return null;

			const address = arrtoip(buf.read('16B'));
			const origin = arrtoip(buf.read('16B'));

			push(other_addresses, {
				ipv6addr_type,
				ipv6addr_type_name: defs.IPV6ADDR_TYPE[ipv6addr_type],
				address,
				origin,
			});
		}

		push(interfaces, {
			if_mac_address,
			linklocal_address,
			other_addresses,
		});
	}

	return interfaces;
};

// 0x19 - Push Button Generic Phy Event
// IEEE1905.1a-2014
decoder[0x19] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const num_phy_media_types = buf.get('B');
	const phy_media_types = [];

	for (let h = 0; h < num_phy_media_types; h++) {
		if (buf.pos() + 5 > end)
			return null;

		const phy_oui = buf.get(3);
		const phy_variant = buf.get('B');
		const media_specific_information_length = buf.get('B');

		if (buf.pos() + media_specific_information_length > end)
			return null;

		const media_specific_information = buf.get(media_specific_information_length);

		push(phy_media_types, {
			phy_oui,
			phy_variant,
			media_specific_information,
		});
	}

	return phy_media_types;
};

// 0x1a - 1905 profile version
// IEEE1905.1a-2014
decoder[0x1a] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const ieee1905_profile = buf.get('B');

	if (!exists(defs.IEEE1905_PROFILE, ieee1905_profile))
		return null;

	return {
		ieee1905_profile,
		ieee1905_profile_name: defs.IEEE1905_PROFILE[ieee1905_profile],
	};
};

// 0x1b - Power off interface
// IEEE1905.1a-2014
decoder[0x1b] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const interface_count = buf.get('B');
	const interfaces = [];

	for (let h = 0; h < interface_count; h++) {
		if (buf.pos() + 13 > end)
			return null;

		const if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const media_type = buf.get('!H');

		if (!exists(defs.MEDIA_TYPE, media_type))
			return null;

		const phy_oui = buf.get(3);
		const phy_variant = buf.get('B');
		const media_specific_information_length = buf.get('B');

		if (buf.pos() + phy_variant > end)
			return null;

		const media_specific_information = buf.get(phy_variant);

		push(interfaces, {
			if_mac_address,
			media_type,
			media_type_name: defs.MEDIA_TYPE[media_type],
			phy_oui,
			phy_variant,
			media_specific_information,
		});
	}

	return interfaces;
};

// 0x1c - Interface power change information
// IEEE1905.1a-2014
decoder[0x1c] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const interface_count = buf.get('B');
	const interfaces = [];

	for (let h = 0; h < interface_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const power_state = buf.get('B');

		if (!exists(defs.POWER_STATE, power_state))
			return null;

		push(interfaces, {
			if_mac_address,
			power_state,
			power_state_name: defs.POWER_STATE[power_state],
		});
	}

	return interfaces;
};

// 0x1d - Interface power change status
// IEEE1905.1a-2014
decoder[0x1d] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const interface_count = buf.get('B');
	const interfaces = [];

	for (let h = 0; h < interface_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const change_state = buf.get('B');

		if (!exists(defs.CHANGE_STATE, change_state))
			return null;

		push(interfaces, {
			if_mac_address,
			change_state,
			change_state_name: defs.CHANGE_STATE[change_state],
		});
	}

	return interfaces;
};

// 0x1e - L2 neighbor device
// IEEE1905.1a-2014
decoder[0x1e] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const interface_count = buf.get('B');
	const interfaces = [];

	for (let h = 0; h < interface_count; h++) {
		if (buf.pos() + 8 > end)
			return null;

		const if_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const neighbor_count = buf.get('!H');
		const neighbors = [];

		for (let i = 0; i < neighbor_count; i++) {
			if (buf.pos() + 8 > end)
				return null;

			const neighbor_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
			const behind_mac_address_count = buf.get('!H');
			const behind_mac_addresses = [];

			for (let j = 0; j < behind_mac_address_count; j++) {
				if (buf.pos() + 6 > end)
					return null;

				const behind_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

				push(behind_mac_addresses, behind_mac_address);
			}

			push(neighbors, {
				neighbor_mac_address,
				behind_mac_addresses,
			});
		}

		push(interfaces, {
			if_mac_address,
			neighbors,
		});
	}

	return interfaces;
};

// 0x80 - Supported Service
// Wi-Fi EasyMesh
decoder[0x80] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const services_count = buf.get('B');
	const services = [];

	for (let h = 0; h < services_count; h++) {
		if (buf.pos() + 1 > end)
			return null;

		const supported_service = buf.get('B');

		if (!exists(defs.SUPPORTED_SERVICE, supported_service))
			return null;

		push(services, supported_service);
	}

	return services;
};

// 0x81 - Searched Service
// Wi-Fi EasyMesh
decoder[0x81] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const services_count = buf.get('B');
	const services = [];

	for (let h = 0; h < services_count; h++) {
		if (buf.pos() + 1 > end)
			return null;

		const searched_service = buf.get('B');

		if (!exists(defs.SEARCHED_SERVICE, searched_service))
			return null;

		push(services, searched_service);
	}

	return services;
};

// 0x82 - AP Radio Identifier
// Wi-Fi EasyMesh
decoder[0x82] = (buf, end) => {
	if (buf.pos() + 6 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return radio_unique_identifier;
};

// 0x83 - AP Operational BSS
// Wi-Fi EasyMesh
decoder[0x83] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const bss_count = buf.get('B');
		const bss = [];

		for (let i = 0; i < bss_count; i++) {
			if (buf.pos() + 7 > end)
				return null;

			const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
			const ssid_length = buf.get('B');

			if (buf.pos() + ssid_length > end)
				return null;

			const ssid = buf.get(ssid_length);

			push(bss, {
				mac_address,
				ssid,
			});
		}

		push(radios, {
			radio_unique_identifier,
			bss,
		});
	}

	return radios;
};

// 0x84 - Associated Clients
// Wi-Fi EasyMesh
decoder[0x84] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const bss_count = buf.get('B');
	const bss = [];

	for (let h = 0; h < bss_count; h++) {
		if (buf.pos() + 8 > end)
			return null;

		const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const clients_count = buf.get('!H');
		const clients = [];

		for (let i = 0; i < clients_count; i++) {
			if (buf.pos() + 8 > end)
				return null;

			const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
			const last_association = buf.get('!H');

			if (last_association > 0xffff)
				return null;

			push(clients, {
				mac_address,
				last_association,
			});
		}

		push(bss, {
			bssid,
			clients,
		});
	}

	return bss;
};

// 0x85 - AP Radio Basic Capabilities
// Wi-Fi EasyMesh
decoder[0x85] = (buf, end) => {
	if (buf.pos() + 8 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const max_bss_supported = buf.get('B');
	const opclass_supported_count = buf.get('B');
	const opclasses_supported = [];

	for (let h = 0; h < opclass_supported_count; h++) {
		if (buf.pos() + 3 > end)
			return null;

		const opclass = buf.get('B');
		const max_txpower_eirp = buf.get('B');
		const statically_non_operable_channels_count = buf.get('B');
		const statically_non_operable_channels = [];

		for (let i = 0; i < statically_non_operable_channels_count; i++) {
			if (buf.pos() + 1 > end)
				return null;

			const channel = buf.get('B');

			push(statically_non_operable_channels, channel);
		}

		push(opclasses_supported, {
			opclass,
			max_txpower_eirp,
			statically_non_operable_channels,
		});
	}

	return {
		radio_unique_identifier,
		max_bss_supported,
		opclasses_supported,
	};
};

// 0x86 - AP HT Capabilities
// Wi-Fi EasyMesh
decoder[0x86] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const max_supported_tx_spatial_streams = (bitfield >> 6) & 0b00000011;
	const max_supported_rx_spatial_streams = (bitfield >> 4) & 0b00000011;
	const short_gi_support_20mhz = ((bitfield & 0b00001000) == 0b00001000);
	const short_gi_support_40mhz = ((bitfield & 0b00000100) == 0b00000100);
	const ht_support_40mhz = ((bitfield & 0b00000010) == 0b00000010);

	return {
		radio_unique_identifier,
		max_supported_tx_spatial_streams,
		max_supported_tx_spatial_streams_name: defs.MAX_SUPPORTED_TX_SPATIAL_STREAMS[max_supported_tx_spatial_streams],
		max_supported_rx_spatial_streams,
		max_supported_rx_spatial_streams_name: defs.MAX_SUPPORTED_RX_SPATIAL_STREAMS[max_supported_rx_spatial_streams],
		short_gi_support_20mhz,
		short_gi_support_40mhz,
		ht_support_40mhz,
	};
};

// 0x87 - AP VHT Capabilities
// Wi-Fi EasyMesh
decoder[0x87] = (buf, end) => {
	if (buf.pos() + 12 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const supported_vht_tx_mcs = buf.get('!H');
	const supported_vht_rx_mcs = buf.get('!H');

	const bitfield = buf.get('B');
	const max_supported_tx_spatial_streams = (bitfield >> 5) & 0b00000111;
	const max_supported_rx_spatial_streams = (bitfield >> 2) & 0b00000111;
	const short_gi_support_80mhz = ((bitfield & 0b00000010) == 0b00000010);
	const short_gi_support_160mhz_8080mhz = ((bitfield & 0b00000001) == 0b00000001);

	const bitfield2 = buf.get('B');
	const vht_support_8080mhz = ((bitfield2 & 0b10000000) == 0b10000000);
	const vht_support_160mhz = ((bitfield2 & 0b01000000) == 0b01000000);
	const su_beamformer_capable = ((bitfield2 & 0b00100000) == 0b00100000);
	const mu_beamformer_capable = ((bitfield2 & 0b00010000) == 0b00010000);

	return {
		radio_unique_identifier,
		supported_vht_tx_mcs,
		supported_vht_rx_mcs,
		max_supported_tx_spatial_streams,
		max_supported_tx_spatial_streams_name: defs.MAX_SUPPORTED_TX_SPATIAL_STREAMS[max_supported_tx_spatial_streams],
		max_supported_rx_spatial_streams,
		max_supported_rx_spatial_streams_name: defs.MAX_SUPPORTED_RX_SPATIAL_STREAMS[max_supported_rx_spatial_streams],
		short_gi_support_80mhz,
		short_gi_support_160mhz_8080mhz,
		vht_support_8080mhz,
		vht_support_160mhz,
		su_beamformer_capable,
		mu_beamformer_capable,
	};
};

// 0x88 - AP HE Capabilities
// Wi-Fi EasyMesh
decoder[0x88] = (buf, end) => {
	if (buf.pos() + 9 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const supported_he_mcs_length = buf.get('B');

	if (buf.pos() + supported_he_mcs_length > end)
		return null;

	const supported_he_mcs = buf.get(supported_he_mcs_length);

	const bitfield = buf.get('B');
	const max_supported_tx_spatial_streams = (bitfield >> 5) & 0b00000111;
	const max_supported_rx_spatial_streams = (bitfield >> 2) & 0b00000111;
	const he_support_8080mhz = ((bitfield & 0b00000010) == 0b00000010);
	const he_support_160mhz = ((bitfield & 0b00000001) == 0b00000001);

	const bitfield2 = buf.get('B');
	const su_beamformer_capable = ((bitfield2 & 0b10000000) == 0b10000000);
	const mu_beamformer_capable = ((bitfield2 & 0b01000000) == 0b01000000);
	const ul_mu_mimo_capable = ((bitfield2 & 0b00100000) == 0b00100000);
	const ul_mu_mimo_ofdma_capable = ((bitfield2 & 0b00010000) == 0b00010000);
	const dl_mu_mimo_ofdma_capable = ((bitfield2 & 0b00001000) == 0b00001000);
	const ul_ofdma_capable = ((bitfield2 & 0b00000100) == 0b00000100);
	const dl_ofdma_capable = ((bitfield2 & 0b00000010) == 0b00000010);

	return {
		radio_unique_identifier,
		supported_he_mcs,
		max_supported_tx_spatial_streams,
		max_supported_tx_spatial_streams_name: defs.MAX_SUPPORTED_TX_SPATIAL_STREAMS[max_supported_tx_spatial_streams],
		max_supported_rx_spatial_streams,
		max_supported_rx_spatial_streams_name: defs.MAX_SUPPORTED_RX_SPATIAL_STREAMS[max_supported_rx_spatial_streams],
		he_support_8080mhz,
		he_support_160mhz,
		su_beamformer_capable,
		mu_beamformer_capable,
		ul_mu_mimo_capable,
		ul_mu_mimo_ofdma_capable,
		dl_mu_mimo_ofdma_capable,
		ul_ofdma_capable,
		dl_ofdma_capable,
	};
};

// 0x89 - Steering Policy
// Wi-Fi EasyMesh
decoder[0x89] = (buf, end) => {
	if (buf.pos() + 3 > end)
		return null;

	const local_steering_disallowed_sta_count = buf.get('B');
	const local_steering_disallowed_sta = [];

	for (let h = 0; h < local_steering_disallowed_sta_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const sta_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(local_steering_disallowed_sta, sta_mac_address);
	}

	const btm_steering_disallowed_sta_count = buf.get('B');
	const btm_steering_disallowed_sta = [];

	for (let h = 0; h < btm_steering_disallowed_sta_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const sta_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(btm_steering_disallowed_sta, sta_mac_address);
	}

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 9 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const steering_policy = buf.get('B');

		if (!exists(defs.STEERING_POLICY, steering_policy))
			return null;

		const channel_utilization_threshold = buf.get('B');
		const rcpi_steering_threshold = buf.get('B');

		if (rcpi_steering_threshold > 0xdc)
			return null;

		push(radios, {
			radio_unique_identifier,
			steering_policy,
			steering_policy_name: defs.STEERING_POLICY[steering_policy],
			channel_utilization_threshold,
			rcpi_steering_threshold,
		});
	}

	return {
		local_steering_disallowed_sta,
		btm_steering_disallowed_sta,
		radios,
	};
};

// 0x8a - Metric Reporting Policy
// Wi-Fi EasyMesh
decoder[0x8a] = (buf, end) => {
	if (buf.pos() + 8 > end)
		return null;

	const ap_metrics_reporting_interval = buf.get('B');

	if (ap_metrics_reporting_interval > 0xff)
		return null;

	const radios_count = buf.get('B');
	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 4 > end)
			return null;

		const sta_metrics_reporting_rcpi_threshold = buf.get('B');

		if (sta_metrics_reporting_rcpi_threshold > 0xdc)
			return null;

		const sta_metrics_reporting_rcpi_hysteresis_margin_override = buf.get('B');
		const ap_metrics_channel_utilization_reporting_threshold = buf.get('B');

		const bitfield = buf.get('B');
		const associated_sta_traffic_stats_inclusion_policy = ((bitfield & 0b10000000) == 0b10000000);
		const associated_sta_link_metrics_inclusion_policy = ((bitfield & 0b01000000) == 0b01000000);
		const associated_wifi6_sta_status_inclusion_policy = ((bitfield & 0b00100000) == 0b00100000);

		push(radios, {
			sta_metrics_reporting_rcpi_threshold,
			sta_metrics_reporting_rcpi_hysteresis_margin_override,
			ap_metrics_channel_utilization_reporting_threshold,
			associated_sta_traffic_stats_inclusion_policy,
			associated_sta_link_metrics_inclusion_policy,
			associated_wifi6_sta_status_inclusion_policy,
		});
	}

	return {
		ap_metrics_reporting_interval,
		radio_unique_identifier,
		radios,
	};
};

// 0x8b - Channel Preference
// Wi-Fi EasyMesh
decoder[0x8b] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const opclass_count = buf.get('B');
	const opclasses = [];

	for (let h = 0; h < opclass_count; h++) {
		if (buf.pos() + 3 > end)
			return null;

		const opclass = buf.get('B');
		const channels_count = buf.get('B');
		const channels = [];

		for (let i = 0; i < channels_count; i++) {
			if (buf.pos() + 1 > end)
				return null;

			push(channels, buf.get('B'));
		}

		const bitfield = buf.get('B');
		const preference = (bitfield >> 4) & 0b00001111;
		const reason_code = bitfield & 0b00001111;

		push(opclasses, {
			opclass,
			channels,
			preference,
			reason_code,
			reason_code_name: defs.CHANNEL_PREFERENCE_REASON_CODE[reason_code],
		});
	}

	return {
		radio_unique_identifier,
		opclasses,
	};
};

// 0x8c - Radio Operation Restriction
// Wi-Fi EasyMesh
decoder[0x8c] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const opclass_count = buf.get('B');
	const opclasses = [];

	for (let h = 0; h < opclass_count; h++) {
		if (buf.pos() + 2 > end)
			return null;

		const opclass = buf.get('B');
		const channels_count = buf.get('B');
		const channels = [];

		for (let i = 0; i < channels_count; i++) {
			if (buf.pos() + 2 > end)
				return null;

			const channel = buf.get('B');
			const minimum_frequency_separation = buf.get('B');

			push(channels, {
				channel,
				minimum_frequency_separation,
			});
		}

		push(opclasses, {
			opclass,
			channels,
		});
	}

	return {
		radio_unique_identifier,
		opclasses,
	};
};

// 0x8d - Transmit Power Limit
// Wi-Fi EasyMesh
decoder[0x8d] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const txpower_limit_eirp = buf.get('B');

	return {
		radio_unique_identifier,
		txpower_limit_eirp,
	};
};

// 0x8e - Channel Selection Response
// Wi-Fi EasyMesh
decoder[0x8e] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const channel_selection_response_code = buf.get('B');

	if (!exists(defs.CHANNEL_SELECTION_RESPONSE_CODE, channel_selection_response_code))
		return null;

	return {
		radio_unique_identifier,
		channel_selection_response_code,
		channel_selection_response_code_name: defs.CHANNEL_SELECTION_RESPONSE_CODE[channel_selection_response_code],
	};
};

// 0x8f - Operating Channel Report
// Wi-Fi EasyMesh
decoder[0x8f] = (buf, end) => {
	if (buf.pos() + 8 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const current_opclass_count = buf.get('B');
	const current_opclass = [];

	for (let h = 0; h < current_opclass_count; h++) {
		if (buf.pos() + 2 > end)
			return null;

		const opclass = buf.get('B');
		const current_operating_channel = buf.get('B');

		push(current_opclass, {
			opclass,
			current_operating_channel,
		});
	}

	const current_txpower_eirp = buf.get('B');

	return {
		radio_unique_identifier,
		current_opclass,
		current_txpower_eirp,
	};
};

// 0x90 - Client Info
// Wi-Fi EasyMesh
decoder[0x90] = (buf, end) => {
	if (buf.pos() + 12 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return {
		bssid,
		mac_address,
	};
};

// 0x91 - Client Capability Report
// Wi-Fi EasyMesh
decoder[0x91] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const result_code = buf.get('B');

	if (!exists(defs.RESULT_CODE, result_code))
		return null;

	let frame_body = null;

	if (result_code == 0) {
		frame_body = buf.get('*');
	}

	return {
		result_code,
		result_code_name: defs.RESULT_CODE[result_code],
		frame_body,
	};
};

// 0x92 - Client Association Event
// Wi-Fi EasyMesh
decoder[0x92] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const association_event = ((bitfield & 0b10000000) == 0b10000000);

	return {
		mac_address,
		bssid,
		association_event,
	};
};

// 0x93 - AP Metric Query
// Wi-Fi EasyMesh
decoder[0x93] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const bssids_count = buf.get('B');
	const bssids = [];

	for (let h = 0; h < bssids_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(bssids, bssid);
	}

	return bssids;
};

// 0x94 - AP Metrics
// Wi-Fi EasyMesh
decoder[0x94] = (buf, end) => {
	if (buf.pos() + 10 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const channel_utilization = buf.get('B');
	const sta_count = buf.get('!H');

	const bitfield = buf.get('B');
	const include_esp_be = ((bitfield & 0b10000000) == 0b10000000);
	const include_esp_bk = ((bitfield & 0b01000000) == 0b01000000);
	const include_esp_vo = ((bitfield & 0b00100000) == 0b00100000);
	const include_esp_vi = ((bitfield & 0b00010000) == 0b00010000);

	let esp_be = null;

	if (include_esp_be == 1) {
		esp_be = buf.get(3);
	}

	let esp_bk = null;

	if (include_esp_bk == 1) {
		esp_bk = buf.get(3);
	}

	let esp_vo = null;

	if (include_esp_vo == 1) {
		esp_vo = buf.get(3);
	}

	let esp_vi = null;

	if (include_esp_vi == 1) {
		esp_vi = buf.get(3);
	}

	return {
		bssid,
		channel_utilization,
		sta_count,
		include_esp_be,
		include_esp_bk,
		include_esp_vo,
		include_esp_vi,
		esp_be,
		esp_bk,
		esp_vo,
		esp_vi,
	};
};

// 0x95 - STA MAC Address Type
// Wi-Fi EasyMesh
decoder[0x95] = (buf, end) => {
	if (buf.pos() + 6 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return mac_address;
};

// 0x96 - Associated STA Link Metrics
// Wi-Fi EasyMesh
decoder[0x96] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bssids_count = buf.get('B');
	const bssids = [];

	for (let h = 0; h < bssids_count; h++) {
		if (buf.pos() + 19 > end)
			return null;

		const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const time_delta = buf.get('!L');
		const estimated_downlink_mac_data_rate = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const estimated_uplink_mac_data_rate = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const uplink_rcpi = buf.get('B');

		if (uplink_rcpi > 0xdc)
			return null;

		push(bssids, {
			bssid,
			time_delta,
			estimated_downlink_mac_data_rate,
			estimated_uplink_mac_data_rate,
			uplink_rcpi,
		});
	}

	return {
		mac_address,
		bssids,
	};
};

// 0x97 - Unassociated STA Link Metrics Query
// Wi-Fi EasyMesh
decoder[0x97] = (buf, end) => {
	if (buf.pos() + 2 > end)
		return null;

	const opclass = buf.get('B');
	const channels_count = buf.get('B');
	const channels = [];

	for (let h = 0; h < channels_count; h++) {
		if (buf.pos() + 2 > end)
			return null;

		const channel = buf.get('B');
		const sta_mac_addresses_count = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const sta_mac_addresses = [];

		for (let i = 0; i < sta_mac_addresses_count; i++) {
			if (buf.pos() + 6 > end)
				return null;

			const sta_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

			push(sta_mac_addresses, sta_mac_address);
		}

		push(channels, {
			channel,
			sta_mac_addresses,
		});
	}

	return {
		opclass,
		channels,
	};
};

// 0x98 - Unassociated STA Link Metrics Response
// Wi-Fi EasyMesh
decoder[0x98] = (buf, end) => {
	if (buf.pos() + 2 > end)
		return null;

	const opclass = buf.get('B');
	const sta_entries_count = buf.get('B');
	const sta_entries = [];

	for (let h = 0; h < sta_entries_count; h++) {
		if (buf.pos() + 12 > end)
			return null;

		const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const channel = buf.get('B');
		const time_delta = buf.get('!L');
		const uplink_rcpi = buf.get('B');

		if (uplink_rcpi > 0xdc)
			return null;

		push(sta_entries, {
			mac_address,
			channel,
			time_delta,
			uplink_rcpi,
		});
	}

	return {
		opclass,
		sta_entries,
	};
};

// 0x99 - Beacon Metrics Query
// Wi-Fi EasyMesh
decoder[0x99] = (buf, end) => {
	if (buf.pos() + 18 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const opclass = buf.get('B');
	const channel = buf.get('B');
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const reporting_detail_value = buf.get('B');
	const ssid_length = buf.get('B');

	if (buf.pos() + ssid_length > end)
		return null;

	const ssid = buf.get(ssid_length);
	const ap_channel_reports_count = buf.get('B');
	const ap_channel_reports = [];

	for (let h = 0; h < ap_channel_reports_count; h++) {
		if (buf.pos() + 1 > end)
			return null;

		const ap_channel_report_length = buf.get('B');
		const opclass = buf.get('B');
		const channels = [];

		for (let i = 0; i < ap_channel_report_length; i++) {
			if (buf.pos() + 1 > end)
				return null;

			push(channels, buf.get('B'));
		}

		push(ap_channel_reports, {
			opclass,
			channels,
		});
	}

	const element_ids_count = buf.get('B');
	const element_list = [];

	for (let h = 0; h < element_ids_count; h++) {
		if (buf.pos() + 1 > end)
			return null;

		push(element_list, buf.get('B'));
	}

	return {
		mac_address,
		opclass,
		channel,
		bssid,
		reporting_detail_value,
		ssid,
		ap_channel_reports,
		element_list,
	};
};

// 0x9a - Beacon Metrics Response
// Wi-Fi EasyMesh
decoder[0x9a] = (buf, end) => {
	if (buf.pos() + 8 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const measurement_report_elements_count = buf.get('B');
	const measurement_report_elements = [];

	for (let h = 0; h < measurement_report_elements_count; h++) {
		if (buf.pos() + 2 > end)
			return null;

		const id = buf.get('B');
		const length = buf.get('B');
		const token = buf.get('B');
		const report_mode = buf.get('B');
		const type = buf.get('B');

		if (buf.pos() + length - 3 > end)
			return null;

		const report_data = buf.get(length - 3);

		push(measurement_report_elements, {
			id,
			token,
			report_mode,
			type,
			report_data,
		});
	}

	return {
		mac_address,
		measurement_report_elements,
	};
};

// 0x9b - Steering Request
// Wi-Fi EasyMesh
decoder[0x9b] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const request_mode = ((bitfield & 0b10000000) == 0b10000000);
	const btm_disassociation_imminent_bit = ((bitfield & 0b01000000) == 0b01000000);
	const btm_abridged_bit = ((bitfield & 0b00100000) == 0b00100000);

	const steering_opportunity_window = buf.get('!H');
	const btm_disassociation_timer = buf.get('!H');
	const sta_list_count = buf.get('B');
	const sta_list = [];

	for (let h = 0; h < sta_list_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const sta_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(sta_list, sta_mac_address);
	}

	const target_bssid_list_count = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const target_bssid_list = [];

	for (let h = 0; h < target_bssid_list_count; h++) {
		if (buf.pos() + 8 > end)
			return null;

		const target_bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const target_bss_opclass = buf.get('B');
		const target_bss_channel = buf.get('B');

		push(target_bssid_list, {
			target_bssid,
			target_bss_opclass,
			target_bss_channel,
		});
	}

	return {
		bssid,
		request_mode,
		btm_disassociation_imminent_bit,
		btm_abridged_bit,
		steering_opportunity_window,
		btm_disassociation_timer,
		sta_list,
		target_bssid_list,
	};
};

// 0x9c - Steering BTM Report
// Wi-Fi EasyMesh
decoder[0x9c] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const sta_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const btm_status_code = buf.get('B');
	const target_bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return {
		bssid,
		sta_mac_address,
		btm_status_code,
		target_bssid,
	};
};

// 0x9d - Client Association Control Request
// Wi-Fi EasyMesh
decoder[0x9d] = (buf, end) => {
	if (buf.pos() + 10 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const association_control = buf.get('B');

	if (!exists(defs.ASSOCIATION_CONTROL, association_control))
		return null;

	const validity_period = buf.get('!H');
	const sta_list_count = buf.get('B');
	const sta_list = [];

	for (let h = 0; h < sta_list_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const sta_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(sta_list, sta_mac_address);
	}

	return {
		bssid,
		association_control,
		association_control_name: defs.ASSOCIATION_CONTROL[association_control],
		validity_period,
		sta_list,
	};
};

// 0x9e - Backhaul Steering Request
// Wi-Fi EasyMesh
decoder[0x9e] = (buf, end) => {
	if (buf.pos() + 14 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const opclass = buf.get('B');
	const channel = buf.get('B');

	return {
		mac_address,
		bssid,
		opclass,
		channel,
	};
};

// 0x9f - Backhaul Steering Response
// Wi-Fi EasyMesh
decoder[0x9f] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const result_code = buf.get('B');

	if (!exists(defs.RESULT_CODE, result_code))
		return null;

	return {
		mac_address,
		bssid,
		result_code,
		result_code_name: defs.RESULT_CODE[result_code],
	};
};

// 0xa0 - Higher Layer Data
// Wi-Fi EasyMesh
decoder[0xa0] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const protocol = buf.get('B');
	const data = buf.get('*');

	return {
		protocol,
		data,
	};
};

// 0xa1 - AP Capability
// Wi-Fi EasyMesh
decoder[0xa1] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const bitfield = buf.get('B');
	const onchannel_unassoc_sta_metrics = ((bitfield & 0b10000000) == 0b10000000);
	const offchannel_unassoc_sta_metrics = ((bitfield & 0b01000000) == 0b01000000);
	const agent_initiated_rcpi_steering = ((bitfield & 0b00100000) == 0b00100000);

	return {
		onchannel_unassoc_sta_metrics,
		offchannel_unassoc_sta_metrics,
		agent_initiated_rcpi_steering,
	};
};

// 0xa2 - Associated STA Traffic Stats
// Wi-Fi EasyMesh
decoder[0xa2] = (buf, end) => {
	if (buf.pos() + 34 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bytes_sent = buf.get('!L');
	const bytes_received = buf.get('!L');
	const packets_sent = buf.get('!L');
	const packets_received = buf.get('!L');
	const tx_packets_errors = buf.get('!L');
	const rx_packets_errors = buf.get('!L');
	const retransmission_count = buf.get('!L');

	return {
		mac_address,
		bytes_sent,
		bytes_received,
		packets_sent,
		packets_received,
		tx_packets_errors,
		rx_packets_errors,
		retransmission_count,
	};
};

// 0xa3 - Error Code
// Wi-Fi EasyMesh
decoder[0xa3] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const reason_code = buf.get('B');

	if (!exists(defs.REASON_CODE, reason_code))
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return {
		reason_code,
		reason_code_name: defs.REASON_CODE[reason_code],
		mac_address,
	};
};

// 0xa4 - Channel Scan Reporting Policy
// Wi-Fi EasyMesh
decoder[0xa4] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const bitfield = buf.get('B');
	const report_independent_channel_scans = ((bitfield & 0b10000000) == 0b10000000);

	return report_independent_channel_scans;
};

// 0xa5 - Channel Scan Capabilities
// Wi-Fi EasyMesh
decoder[0xa5] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 12 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		const bitfield = buf.get('B');
		const on_boot_only = ((bitfield & 0b10000000) == 0b10000000);
		const scan_impact = (bitfield >> 5) & 0b00000011;

		const minimum_scan_interval = buf.get('!L');
		const opclass_count = buf.get('B');
		const opclass = [];

		for (let i = 0; i < opclass_count; i++) {
			if (buf.pos() + 2 > end)
				return null;

			const opclass = buf.get('B');
			const channels_count = buf.get('B');
			const channels = [];

			for (let j = 0; j < channels_count; j++) {
				if (buf.pos() + 1 > end)
					return null;

				push(channels, buf.get('B'));
			}

			push(opclass, {
				opclass,
				channels,
			});
		}

		push(radios, {
			radio_unique_identifier,
			on_boot_only,
			scan_impact,
			scan_impact_name: defs.SCAN_IMPACT[scan_impact],
			minimum_scan_interval,
			opclass,
		});
	}

	return radios;
};

// 0xa6 - Channel Scan Request
// Wi-Fi EasyMesh
decoder[0xa6] = (buf, end) => {
	if (buf.pos() + 2 > end)
		return null;

	const bitfield = buf.get('B');
	const perform_fresh_scan = ((bitfield & 0b10000000) == 0b10000000);

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const opclass_count = buf.get('B');
		const opclass = [];

		for (let i = 0; i < opclass_count; i++) {
			if (buf.pos() + 2 > end)
				return null;

			const opclass = buf.get('B');
			const channels_count = buf.get('B');
			const channels = [];

			for (let j = 0; j < channels_count; j++) {
				if (buf.pos() + 1 > end)
					return null;

				push(channels, buf.get('B'));
			}

			push(opclass, {
				opclass,
				channels,
			});
		}

		push(radios, {
			radio_unique_identifier,
			opclass,
		});
	}

	return {
		perform_fresh_scan,
		radios,
	};
};

// 0xa7 - Channel Scan Result
// Wi-Fi EasyMesh
decoder[0xa7] = (buf, end) => {
	if (buf.pos() + 19 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const opclass = buf.get('B');
	const channel = buf.get('B');
	const scan_status = buf.get('B');

	if (!exists(defs.SCAN_STATUS, scan_status))
		return null;

	const timestamp_length = buf.get('B');

	if (buf.pos() + timestamp_length > end)
		return null;

	const timestamp = buf.get(timestamp_length);
	const utilization = buf.get('B');
	const noise = buf.get('B');
	const number_of_neighbors = buf.get('!H');
	const neighbors = [];

	for (let h = 0; h < number_of_neighbors; h++) {
		if (buf.pos() + 13 > end)
			return null;

		const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const ssid_length = buf.get('B');

		if (ssid_length > 0x20)
			return null;

		if (buf.pos() + ssid_length > end)
			return null;

		const ssid = buf.get(ssid_length);
		const signal_strength = buf.get('B');
		const channel_bandwidth_length = buf.get('B');

		if (buf.pos() + channel_bandwidth_length > end)
			return null;

		const channel_bandwidth = buf.get(channel_bandwidth_length);

		const bitfield = buf.get('B');
		const bss_load_element_present = ((bitfield & 0b10000000) == 0b10000000);
		const bss_color = bitfield & 0b00111111;

		const channel_utilization = buf.get('B');
		const station_count = buf.get('!H');

		push(neighbors, {
			bssid,
			ssid,
			signal_strength,
			channel_bandwidth,
			bss_load_element_present,
			bss_color,
			channel_utilization,
			station_count,
		});
	}

	const aggregate_scan_duration = buf.get('!L');

	const bitfield = buf.get('B');
	const scan_type = ((bitfield & 0b10000000) == 0b10000000);

	return {
		radio_unique_identifier,
		opclass,
		channel,
		scan_status,
		scan_status_name: defs.SCAN_STATUS[scan_status],
		timestamp,
		utilization,
		noise,
		neighbors,
		aggregate_scan_duration,
		scan_type,
	};
};

// 0xa8 - Timestamp
// Wi-Fi EasyMesh
decoder[0xa8] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const timestamp_length = buf.get('B');

	if (buf.pos() + timestamp_length > end)
		return null;

	const timestamp = buf.get(timestamp_length);

	return timestamp;
};

// 0xa9 - 1905 Layer Security Capability
// Wi-Fi EasyMesh
decoder[0xa9] = (buf, end) => {
	if (buf.pos() + 3 > end)
		return null;

	const onboarding_protocol = buf.get('B');
	const mic_algorithm = buf.get('B');
	const encryption_algorithm = buf.get('B');

	return {
		onboarding_protocol,
		mic_algorithm,
		encryption_algorithm,
	};
};

// 0xaa - AP Wi-Fi 6 Capabilities
// Wi-Fi EasyMesh
decoder[0xaa] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const roles_count = buf.get('B');
	const roles = [];

	for (let h = 0; h < roles_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const bitfield = buf.get('B');
		const agent_role = (bitfield >> 6) & 0b00000011;
		const he_160 = ((bitfield & 0b00100000) == 0b00100000);
		const he_8080 = ((bitfield & 0b00010000) == 0b00010000);
		const mcs_nss_length = bitfield & 0b00001111;

		if (buf.pos() + mcs_nss_length > end)
			return null;

		const mcs_nss = buf.get(mcs_nss_length);

		const bitfield2 = buf.get('B');
		const su_beamformer = ((bitfield2 & 0b10000000) == 0b10000000);
		const su_beamformee = ((bitfield2 & 0b01000000) == 0b01000000);
		const mu_beamformer_status = ((bitfield2 & 0b00100000) == 0b00100000);
		const beamformee_sts_less_80 = ((bitfield2 & 0b00010000) == 0b00010000);
		const beamformee_sts_greater_80 = ((bitfield2 & 0b00001000) == 0b00001000);
		const ul_mu_mimo = ((bitfield2 & 0b00000100) == 0b00000100);
		const ul_ofdma = ((bitfield2 & 0b00000010) == 0b00000010);
		const dl_ofdma = ((bitfield2 & 0b00000001) == 0b00000001);

		const bitfield3 = buf.get('B');
		const max_dl_mu_mimo_tx = (bitfield3 >> 4) & 0b00001111;
		const max_ul_mu_mimo_rx = bitfield3 & 0b00001111;

		const max_dl_ofdma_tx = buf.get('B');
		const max_ul_ofdma_rx = buf.get('B');

		const bitfield4 = buf.get('B');
		const rts = ((bitfield4 & 0b10000000) == 0b10000000);
		const mu_rts = ((bitfield4 & 0b01000000) == 0b01000000);
		const multi_bssid = ((bitfield4 & 0b00100000) == 0b00100000);
		const mu_edca = ((bitfield4 & 0b00010000) == 0b00010000);
		const twt_requester = ((bitfield4 & 0b00001000) == 0b00001000);
		const twt_responder = ((bitfield4 & 0b00000100) == 0b00000100);
		const spatial_reuse = ((bitfield4 & 0b00000010) == 0b00000010);
		const anticipated_channel_usage = ((bitfield4 & 0b00000001) == 0b00000001);

		push(roles, {
			agent_role,
			he_160,
			he_8080,
			mcs_nss,
			su_beamformer,
			su_beamformee,
			mu_beamformer_status,
			beamformee_sts_less_80,
			beamformee_sts_greater_80,
			ul_mu_mimo,
			ul_ofdma,
			dl_ofdma,
			max_dl_mu_mimo_tx,
			max_ul_mu_mimo_rx,
			max_dl_ofdma_tx,
			max_ul_ofdma_rx,
			rts,
			mu_rts,
			multi_bssid,
			mu_edca,
			twt_requester,
			twt_responder,
			spatial_reuse,
			anticipated_channel_usage,
		});
	}

	return {
		radio_unique_identifier,
		roles,
	};
};

// 0xab - MIC
// Wi-Fi EasyMesh
decoder[0xab] = (buf, end) => {
	if (buf.pos() + 15 > end)
		return null;

	const bitfield = buf.get('B');
	const gtk_key_id = (bitfield >> 6) & 0b00000011;
	const mic_version = (bitfield >> 4) & 0b00000011;

	const integrity_transmission_counter = buf.get(6);
	const source_1905_al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const mic_length = buf.get('!H');

	if (buf.pos() + mic_length > end)
		return null;

	const mic = buf.get(mic_length);

	return {
		gtk_key_id,
		mic_version,
		integrity_transmission_counter,
		source_1905_al_mac_address,
		mic,
	};
};

// 0xac - Encrypted
// Wi-Fi EasyMesh
decoder[0xac] = (buf, end) => {
	if (buf.pos() + 20 > end)
		return null;

	const encryption_transmission_counter = buf.get(6);
	const source_1905_al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const destination_1905_al_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const aes_siv_length = buf.get('!H');

	if (buf.pos() + aes_siv_length > end)
		return null;

	const aes_siv = buf.get(aes_siv_length);

	return {
		encryption_transmission_counter,
		source_1905_al_mac_address,
		destination_1905_al_mac_address,
		aes_siv,
	};
};

// 0xad - CAC Request
// Wi-Fi EasyMesh
decoder[0xad] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 9 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const opclass = buf.get('B');
		const channel = buf.get('B');

		const bitfield = buf.get('B');
		const cac_method = (bitfield >> 5) & 0b00000111;
		const cac_completion_action = (bitfield >> 3) & 0b00000011;

		push(radios, {
			radio_unique_identifier,
			opclass,
			channel,
			cac_method,
			cac_completion_action,
		});
	}

	return radios;
};

// 0xae - CAC Termination
// Wi-Fi EasyMesh
decoder[0xae] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 8 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const opclass = buf.get('B');
		const channel = buf.get('B');

		push(radios, {
			radio_unique_identifier,
			opclass,
			channel,
		});
	}

	return radios;
};

// 0xaf - CAC Completion Report
// Wi-Fi EasyMesh
decoder[0xaf] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 10 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const opclass = buf.get('B');
		const channel = buf.get('B');
		const cac_completion_status = buf.get('B');

		if (!exists(defs.CAC_COMPLETION_STATUS, cac_completion_status))
			return null;

		const pairs_count = buf.get('B');
		const pairs = [];

		for (let i = 0; i < pairs_count; i++) {
			if (buf.pos() + 2 > end)
				return null;

			const opclass_detected = buf.get('B');
			const channel_detected = buf.get('B');

			push(pairs, {
				opclass_detected,
				channel_detected,
			});
		}

		push(radios, {
			radio_unique_identifier,
			opclass,
			channel,
			cac_completion_status,
			cac_completion_status_name: defs.CAC_COMPLETION_STATUS[cac_completion_status],
			pairs,
		});
	}

	return radios;
};

// 0xb0 - Associated Wi-Fi 6 STA Status Report
// Wi-Fi EasyMesh
decoder[0xb0] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const n = buf.get('B');
	const n2 = [];

	for (let h = 0; h < n; h++) {
		if (buf.pos() + 2 > end)
			return null;

		const tid = buf.get('B');
		const queue_size = buf.get('B');

		push(n2, {
			tid,
			queue_size,
		});
	}

	return {
		mac_address,
		n2,
	};
};

// 0xb1 - CAC Status Report
// Wi-Fi EasyMesh
decoder[0xb1] = (buf, end) => {
	if (buf.pos() + 3 > end)
		return null;

	const available_channels_count = buf.get('B');
	const available_channels = [];

	for (let h = 0; h < available_channels_count; h++) {
		if (buf.pos() + 4 > end)
			return null;

		const opclass = buf.get('B');
		const channel = buf.get('B');
		const minutes = buf.get('!H');

		push(available_channels, {
			opclass,
			channel,
			minutes,
		});
	}

	const radar_detected_channels_count = buf.get('B');
	const radar_detected_channels = [];

	for (let h = 0; h < radar_detected_channels_count; h++) {
		if (buf.pos() + 4 > end)
			return null;

		const opclass = buf.get('B');
		const channel = buf.get('B');
		const duration = buf.get('!H');

		push(radar_detected_channels, {
			opclass,
			channel,
			duration,
		});
	}

	const active_cac_channels_count = buf.get('B');
	const active_cac_channels = [];

	for (let h = 0; h < active_cac_channels_count; h++) {
		if (buf.pos() + 5 > end)
			return null;

		const opclass = buf.get('B');
		const channel = buf.get('B');
		const countdown = buf.get(3);

		push(active_cac_channels, {
			opclass,
			channel,
			countdown,
		});
	}

	return {
		available_channels,
		radar_detected_channels,
		active_cac_channels,
	};
};

// 0xb2 - CAC Capabilities
// Wi-Fi EasyMesh
decoder[0xb2] = (buf, end) => {
	if (buf.pos() + 3 > end)
		return null;

	const country_code = buf.get(2);
	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const cac_types_supported_count = buf.get('B');
		const cac_types_supported = [];

		for (let i = 0; i < cac_types_supported_count; i++) {
			if (buf.pos() + 5 > end)
				return null;

			const cac_method_supported = buf.get('B');

			if (!exists(defs.CAC_METHOD_SUPPORTED, cac_method_supported))
				return null;

			const duration = buf.get(3);
			const opclass_count = buf.get('B');
			const opclasses = [];

			for (let j = 0; j < opclass_count; j++) {
				if (buf.pos() + 2 > end)
					return null;

				const opclass = buf.get('B');
				const channels_count = buf.get('B');
				const channels = [];

				for (let k = 0; k < channels_count; k++) {
					if (buf.pos() + 1 > end)
						return null;

					const channel = buf.get('B');

					push(channels, channel);
				}

				push(opclasses, {
					opclass,
					channels,
				});
			}

			push(cac_types_supported, {
				cac_method_supported,
				cac_method_supported_name: defs.CAC_METHOD_SUPPORTED[cac_method_supported],
				duration,
				opclasses,
			});
		}

		push(radios, {
			radio_unique_identifier,
			cac_types_supported,
		});
	}

	return {
		country_code,
		radios,
	};
};

// 0xb3 - Multi-AP Profile
// Wi-Fi EasyMesh
decoder[0xb3] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const profile = buf.get('B');

	if (!exists(defs.MULTI_AP_PROFILE, profile))
		return null;

	return {
		profile,
		profile_name: defs.MULTI_AP_PROFILE[profile],
	};
};

// 0xb4 - Profile-2 AP Capability
// Wi-Fi EasyMesh
decoder[0xb4] = (buf, end) => {
	if (buf.pos() + 4 > end)
		return null;

	const max_prioritization_rules = buf.get('B');

	const bitfield = buf.get('B');
	const byte_counter_unit = (bitfield >> 6) & 0b00000011;
	const supports_prioritization = ((bitfield & 0b00100000) == 0b00100000);
	const supports_dpp_onboarding = ((bitfield & 0b00010000) == 0b00010000);
	const supports_traffic_separation = ((bitfield & 0b00001000) == 0b00001000);

	const max_unique_vids = buf.get('B');

	return {
		max_prioritization_rules,
		byte_counter_unit,
		byte_counter_unit_name: defs.BYTE_COUNTER_UNIT[byte_counter_unit],
		supports_prioritization,
		supports_dpp_onboarding,
		supports_traffic_separation,
		max_unique_vids,
	};
};

// 0xb5 - Default 802.1Q Settings
// Wi-Fi EasyMesh
decoder[0xb5] = (buf, end) => {
	if (buf.pos() + 3 > end)
		return null;

	const primary_vlan_id = buf.get('!H');

	const bitfield = buf.get('B');
	const default_pcp = (bitfield >> 5) & 0b00000111;

	return {
		primary_vlan_id,
		default_pcp,
	};
};

// 0xb6 - Traffic Separation Policy
// Wi-Fi EasyMesh
decoder[0xb6] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const ssids_count = buf.get('B');
	const ssids = [];

	for (let h = 0; h < ssids_count; h++) {
		if (buf.pos() + 3 > end)
			return null;

		const ssid_name_length = buf.get('B');

		if (buf.pos() + ssid_name_length > end)
			return null;

		const ssid_name = buf.get(ssid_name_length);
		const vlan_id = buf.get('!H');

		push(ssids, {
			ssid_name,
			vlan_id,
		});
	}

	return ssids;
};

// 0xb7 - BSS Configuration Report TLV format BSSID
// Wi-Fi EasyMesh
decoder[0xb7] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const bss_count = buf.get('B');
		const bss = [];

		for (let i = 0; i < bss_count; i++) {
			if (buf.pos() + 9 > end)
				return null;

			const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

			const bitfield = buf.get('B');
			const backhaul = ((bitfield & 0b10000000) == 0b10000000);
			const fronthaul = ((bitfield & 0b01000000) == 0b01000000);
			const r1_disallowed_status = ((bitfield & 0b00100000) == 0b00100000);
			const r2_disallowed_status = ((bitfield & 0b00010000) == 0b00010000);
			const multiple_bssid = ((bitfield & 0b00001000) == 0b00001000);
			const transmitted_bssid = ((bitfield & 0b00000100) == 0b00000100);

			const ssid_length = buf.get('B');

			if (buf.pos() + ssid_length > end)
				return null;

			const ssid = buf.get(ssid_length);

			push(bss, {
				bssid,
				backhaul,
				fronthaul,
				r1_disallowed_status,
				r2_disallowed_status,
				multiple_bssid,
				transmitted_bssid,
				ssid,
			});
		}

		push(radios, {
			radio_unique_identifier,
			bss,
		});
	}

	return radios;
};

// 0xb8 - BSSID
// Wi-Fi EasyMesh
decoder[0xb8] = (buf, end) => {
	if (buf.pos() + 6 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return bssid;
};

// 0xb9 - Service Prioritization Rule
// Wi-Fi EasyMesh
decoder[0xb9] = (buf, end) => {
	if (buf.pos() + 8 > end)
		return null;

	const rule_id = buf.get('!L');

	const bitfield = buf.get('B');
	const add_remove = ((bitfield & 0b10000000) == 0b10000000);

	const precedence = buf.get('B');
	const output = buf.get('B');

	const bitfield2 = buf.get('B');
	const always_match = ((bitfield2 & 0b10000000) == 0b10000000);

	return {
		rule_id,
		add_remove,
		precedence,
		output,
		always_match,
	};
};

// 0xba - DSCP Mapping Table
// Wi-Fi EasyMesh
decoder[0xba] = (buf, end) => {
	const dscp_pcp_mapping = [];

	while (buf.pos() + 1 < end) {
		const pcp_value = buf.get('B');

		push(dscp_pcp_mapping, pcp_value);
	}

	return dscp_pcp_mapping;
};

// 0xbb - BSS Configuration Request
// Wi-Fi EasyMesh
decoder[0xbb] = (buf, end) => buf.get(end - buf.pos()),

// 0xbc - Profile-2 Error Code
// Wi-Fi EasyMesh
decoder[0xbc] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const reason_code = buf.get('B');

	if (!exists(defs.PROFILE_2_REASON_CODE, reason_code))
		return null;

	let bssid = null;

	if (reason_code in [ 7, 8 ]) {
		bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	}

	let service_prio_rule_id = null;

	if (reason_code in [ 1, 2 ]) {
		service_prio_rule_id = buf.get('!L');
	}

	let qmid = null;

	if (reason_code == 11) {
		qmid = buf.get('!H');
	}

	return {
		reason_code,
		reason_code_name: defs.PROFILE_2_REASON_CODE[reason_code],
		bssid,
		service_prio_rule_id,
		qmid,
	};
};

// 0xbd - BSS Configuration Response
// Wi-Fi EasyMesh
decoder[0xbd] = (buf, end) => buf.get(end - buf.pos()),

// 0xbe - AP Radio Advanced Capabilities
// Wi-Fi EasyMesh
decoder[0xbe] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const combined_front_back = ((bitfield & 0b10000000) == 0b10000000);
	const combined_profile1_profile2 = ((bitfield & 0b01000000) == 0b01000000);
	const mscs = ((bitfield & 0b00100000) == 0b00100000);
	const scs = ((bitfield & 0b00010000) == 0b00010000);
	const qos_map = ((bitfield & 0b00001000) == 0b00001000);
	const dscp_policy = ((bitfield & 0b00000100) == 0b00000100);

	return {
		radio_unique_identifier,
		combined_front_back,
		combined_profile1_profile2,
		mscs,
		scs,
		qos_map,
		dscp_policy,
	};
};

// 0xbf - Association Status Notification
// Wi-Fi EasyMesh
decoder[0xbf] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const bssids_count = buf.get('B');
	const bssids = [];

	for (let h = 0; h < bssids_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const association_allowance_status = buf.get('B');

		if (!exists(defs.ASSOCIATION_ALLOWANCE_STATUS, association_allowance_status))
			return null;

		push(bssids, {
			bssid,
			association_allowance_status,
			association_allowance_status_name: defs.ASSOCIATION_ALLOWANCE_STATUS[association_allowance_status],
		});
	}

	return bssids;
};

// 0xc0 - Source Info
// Wi-Fi EasyMesh
decoder[0xc0] = (buf, end) => {
	if (buf.pos() + 6 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return mac_address;
};

// 0xc1 - Tunneled message type
// Wi-Fi EasyMesh
decoder[0xc1] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const tunneled_protocol_type = buf.get('B');

	if (!exists(defs.TUNNELED_PROTOCOL_TYPE, tunneled_protocol_type))
		return null;

	return {
		tunneled_protocol_type,
		tunneled_protocol_type_name: defs.TUNNELED_PROTOCOL_TYPE[tunneled_protocol_type],
	};
};

// 0xc2 - Tunneled
// Wi-Fi EasyMesh
decoder[0xc2] = (buf, end) => buf.get(end - buf.pos()),

// 0xc3 - Profile-2 Steering Request
// Wi-Fi EasyMesh
decoder[0xc3] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const request_mode = ((bitfield & 0b10000000) == 0b10000000);
	const btm_disassociation_imminent_bit = ((bitfield & 0b01000000) == 0b01000000);
	const btm_abridged_bit = ((bitfield & 0b00100000) == 0b00100000);

	const steering_opportunity_window = buf.get('!H');
	const btm_disassociation_timer = buf.get('!H');
	const sta_list_count = buf.get('B');
	const sta_list = [];

	for (let h = 0; h < sta_list_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(sta_list, mac_address);
	}

	const target_bssid_count = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const target_bssids = [];

	for (let h = 0; h < target_bssid_count; h++) {
		if (buf.pos() + 9 > end)
			return null;

		const target_bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const target_bss_opclass = buf.get('B');
		const target_bss_channel = buf.get('B');
		const reason_code = buf.get('B');

		push(target_bssids, {
			target_bssid,
			target_bss_opclass,
			target_bss_channel,
			reason_code,
		});
	}

	return {
		bssid,
		request_mode,
		btm_disassociation_imminent_bit,
		btm_abridged_bit,
		steering_opportunity_window,
		btm_disassociation_timer,
		sta_list,
		target_bssids,
	};
};

// 0xc4 - Unsuccessful Association Policy
// Wi-Fi EasyMesh
decoder[0xc4] = (buf, end) => {
	if (buf.pos() + 5 > end)
		return null;

	const bitfield = buf.get('B');
	const report_unsuccessful_assocs = ((bitfield & 0b10000000) == 0b10000000);

	const max_reporting_rate = buf.get('!L');

	return {
		report_unsuccessful_assocs,
		max_reporting_rate,
	};
};

// 0xc5 - Metric Collection Interval
// Wi-Fi EasyMesh
decoder[0xc5] = (buf, end) => {
	if (buf.pos() + 4 > end)
		return null;

	const collection_interval = buf.get('!L');

	return collection_interval;
};

// 0xc6 - Radio Metrics
// Wi-Fi EasyMesh
decoder[0xc6] = (buf, end) => {
	if (buf.pos() + 10 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const noise = buf.get('B');
	const transmit = buf.get('B');
	const receive_self = buf.get('B');
	const receive_other = buf.get('B');

	return {
		radio_unique_identifier,
		noise,
		transmit,
		receive_self,
		receive_other,
	};
};

// 0xc7 - AP Extended Metrics
// Wi-Fi EasyMesh
decoder[0xc7] = (buf, end) => {
	if (buf.pos() + 30 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const unicast_bytes_sent = buf.get('!L');
	const unicast_bytes_received = buf.get('!L');
	const multicast_bytes_sent = buf.get('!L');
	const multicast_bytes_received = buf.get('!L');
	const broadcast_bytes_sent = buf.get('!L');
	const broadcast_bytes_received = buf.get('!L');

	return {
		bssid,
		unicast_bytes_sent,
		unicast_bytes_received,
		multicast_bytes_sent,
		multicast_bytes_received,
		broadcast_bytes_sent,
		broadcast_bytes_received,
	};
};

// 0xc8 - Associated STA Extended Link Metrics
// Wi-Fi EasyMesh
decoder[0xc8] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bssids_count = buf.get('B');
	const bssids = [];

	for (let h = 0; h < bssids_count; h++) {
		if (buf.pos() + 22 > end)
			return null;

		const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const last_data_downlink_rate = buf.get('!L');
		const last_data_uplink_rate = buf.get('!L');
		const utilization_receive = buf.get('!L');
		const utilization_transmit = buf.get('!L');

		push(bssids, {
			bssid,
			last_data_downlink_rate,
			last_data_uplink_rate,
			utilization_receive,
			utilization_transmit,
		});
	}

	return {
		mac_address,
		bssids,
	};
};

// 0xc9 - Status Code
// Wi-Fi EasyMesh
decoder[0xc9] = (buf, end) => {
	if (buf.pos() + 4 > end)
		return null;

	const octets_count = buf.get('!H');
	const status_code = buf.get('!H');

	return {
		octets_count,
		status_code,
	};
};

// 0xca - Reason Code
// Wi-Fi EasyMesh
decoder[0xca] = (buf, end) => {
	if (buf.pos() + 2 > end)
		return null;

	const reason_code = buf.get('!H');

	return reason_code;
};

// 0xcb - Backhaul STA Radio Capabilities
// Wi-Fi EasyMesh
decoder[0xcb] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const mac_address_included = ((bitfield & 0b10000000) == 0b10000000);

	const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return {
		radio_unique_identifier,
		mac_address_included,
		mac_address,
	};
};

// 0xcc - AKM Suite Capabilities
// Wi-Fi EasyMesh
decoder[0xcc] = (buf, end) => {
	if (buf.pos() + 2 > end)
		return null;

	const backhaul_akm_suite_selectors_count = buf.get('B');
	const backhaul_akm_suite_selectors = [];

	for (let h = 0; h < backhaul_akm_suite_selectors_count; h++) {
		if (buf.pos() + 4 > end)
			return null;

		const bh_oui = buf.get(3);
		const bh_akm_suite_type = buf.get('B');

		push(backhaul_akm_suite_selectors, {
			bh_oui,
			bh_akm_suite_type,
		});
	}

	const fronthaul_akm_suite_selectors_count = buf.get('B');
	const fronthaul_akm_suite_selectors = [];

	for (let h = 0; h < fronthaul_akm_suite_selectors_count; h++) {
		if (buf.pos() + 4 > end)
			return null;

		const fh_oui = buf.get(3);
		const fh_akm_suite_type = buf.get('B');

		push(fronthaul_akm_suite_selectors, {
			fh_oui,
			fh_akm_suite_type,
		});
	}

	return {
		backhaul_akm_suite_selectors,
		fronthaul_akm_suite_selectors,
	};
};

// 0xcd - 1905 Encap DPP
// Wi-Fi EasyMesh
decoder[0xcd] = (buf, end) => {
	if (buf.pos() + 10 > end)
		return null;

	const bitfield = buf.get('B');
	const enrollee_mac_address_present = ((bitfield & 0b10000000) == 0b10000000);
	const dpp_frame_indicator = ((bitfield & 0b00100000) == 0b00100000);

	const destination_sta_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const frame_type = buf.get('B');
	const encapsulated_frame_length = buf.get('!H');

	if (buf.pos() + encapsulated_frame_length > end)
		return null;

	const encapsulated_frame = buf.get(encapsulated_frame_length);

	return {
		enrollee_mac_address_present,
		dpp_frame_indicator,
		destination_sta_mac_address,
		frame_type,
		encapsulated_frame,
	};
};

// 0xce - 1905 Encap EAPOL
// Wi-Fi EasyMesh
decoder[0xce] = (buf, end) => buf.get(end - buf.pos()),

// 0xcf - DPP Bootstrapping URI Notification
// Wi-Fi EasyMesh
decoder[0xcf] = (buf, end) => {
	if (buf.pos() + 18 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const backhaul_sta_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const dpp_uri = buf.get('*');

	return {
		radio_unique_identifier,
		bssid,
		backhaul_sta_address,
		dpp_uri,
	};
};

// 0xd0 - Backhaul BSS Configuration
// Wi-Fi EasyMesh
decoder[0xd0] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const profile1_backhaul_sta_disallowed = ((bitfield & 0b10000000) == 0b10000000);
	const profile2_backhaul_sta_disallowed = ((bitfield & 0b01000000) == 0b01000000);

	return {
		bssid,
		profile1_backhaul_sta_disallowed,
		profile2_backhaul_sta_disallowed,
	};
};

// 0xd1 - DPP Message
// Wi-Fi EasyMesh
decoder[0xd1] = (buf, end) => buf.get(end - buf.pos()),

// 0xd2 - DPP CCE Indication
// Wi-Fi EasyMesh
decoder[0xd2] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const advertise_cce = buf.get('B');

	if (!exists(defs.ADVERTISE_CCE, advertise_cce))
		return null;

	return {
		advertise_cce,
		advertise_cce_name: defs.ADVERTISE_CCE[advertise_cce],
	};
};

// 0xd3 - DPP Chirp Value
// Wi-Fi EasyMesh
decoder[0xd3] = (buf, end) => {
	if (buf.pos() + 8 > end)
		return null;

	const bitfield = buf.get('B');
	const enrollee_mac_address_present = ((bitfield & 0b10000000) == 0b10000000);
	const hash_validity = ((bitfield & 0b01000000) == 0b01000000);

	const destination_sta_mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const hash_length = buf.get('B');

	if (buf.pos() + hash_length > end)
		return null;

	const hash_value = buf.get(hash_length);

	return {
		enrollee_mac_address_present,
		hash_validity,
		destination_sta_mac_address,
		hash_value,
	};
};

// 0xd4 - Device Inventory
// Wi-Fi EasyMesh
decoder[0xd4] = (buf, end) => {
	if (buf.pos() + 4 > end)
		return null;

	const serial_number_length = buf.get('B');

	if (buf.pos() + serial_number_length > end)
		return null;

	const serial_number = buf.get(serial_number_length);
	const length = buf.get('B');

	if (buf.pos() + length > end)
		return null;

	const software_version = buf.get(length);
	const execution_env_length = buf.get('B');

	if (buf.pos() + execution_env_length > end)
		return null;

	const execution_env = buf.get(execution_env_length);
	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const chipset_vendor_length = buf.get('B');

		if (buf.pos() + chipset_vendor_length > end)
			return null;

		const chipset_vendor = buf.get(chipset_vendor_length);

		push(radios, {
			radio_unique_identifier,
			chipset_vendor,
		});
	}

	return {
		serial_number,
		software_version,
		execution_env,
		radios,
	};
};

// 0xd5 - Agent List
// Wi-Fi EasyMesh
decoder[0xd5] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const multi_ap_agents_present_count = buf.get('B');
	const multi_ap_agents_present = [];

	for (let h = 0; h < multi_ap_agents_present_count; h++) {
		if (buf.pos() + 8 > end)
			return null;

		const mac_address = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const multi_ap_profile = buf.get('B');

		if (!exists(defs.MULTI_AP_PROFILE, multi_ap_profile))
			return null;

		const security = buf.get('B');

		if (security > 0xff)
			return null;

		push(multi_ap_agents_present, {
			mac_address,
			multi_ap_profile,
			multi_ap_profile_name: defs.MULTI_AP_PROFILE[multi_ap_profile],
			security,
		});
	}

	return multi_ap_agents_present;
};

// 0xd6 - Anticipated Channel Preference
// Wi-Fi EasyMesh
decoder[0xd6] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const opclass_count = buf.get('B');
	const opclasses = [];

	for (let h = 0; h < opclass_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const opclass = buf.get('B');
		const channels_count = buf.get('B');
		const channels = [];

		for (let i = 0; i < channels_count; i++) {
			if (buf.pos() + 1 > end)
				return null;

			push(channels, buf.get('B'));
		}

		push(opclasses, {
			opclass,
			channels,
		});
	}

	return opclasses;
};

// 0xd7 - Anticipated Channel Usage
// Wi-Fi EasyMesh
decoder[0xd7] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const opclass = buf.get('B');
	const channel = buf.get('B');
	const reference_bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const usage_entries_count = buf.get('B');
	const burst_start_time = buf.get('!L');
	const usage_entries = [];

	for (let h = 0; h < usage_entries_count; h++) {
		if (buf.pos() + 25 > end)
			return null;

		const burst_length = buf.get('!L');
		const repetitions_count = buf.get('!L');
		const burst_interval = buf.get('!L');
		const ru_bitmask_length = buf.get('B');

		if (buf.pos() + ru_bitmask_length > end)
			return null;

		const ru_bitmask = buf.get(ru_bitmask_length);
		const transmitter_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const power_level = buf.get('B');
		const channel_usage_reason = buf.get('B');

		push(usage_entries, {
			burst_length,
			repetitions_count,
			burst_interval,
			ru_bitmask,
			transmitter_identifier,
			power_level,
			channel_usage_reason,
		});
	}

	return {
		opclass,
		channel,
		reference_bssid,
		burst_start_time,
		usage_entries,
	};
};

// 0xd8 - Spatial Reuse Request
// Wi-Fi EasyMesh
decoder[0xd8] = (buf, end) => {
	if (buf.pos() + 29 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const bss_color = bitfield & 0b00111111;

	const bitfield2 = buf.get('B');
	const hesiga_spatial_reuse_value15_allowed = ((bitfield2 & 0b00010000) == 0b00010000);
	const srg_information_valid = ((bitfield2 & 0b00001000) == 0b00001000);
	const non_srg_offset_valid = ((bitfield2 & 0b00000100) == 0b00000100);
	const psr_disallowed = ((bitfield2 & 0b00000001) == 0b00000001);

	const non_srg_obsspd_max_offset = buf.get('B');
	const srg_obsspd_min_offset = buf.get('B');
	const srg_obsspd_max_offset = buf.get('B');
	const srg_bss_color_bitmap = buf.get('!Q');
	const srg_partial_bssid_bitmap = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return {
		radio_unique_identifier,
		bss_color,
		hesiga_spatial_reuse_value15_allowed,
		srg_information_valid,
		non_srg_offset_valid,
		psr_disallowed,
		non_srg_obsspd_max_offset,
		srg_obsspd_min_offset,
		srg_obsspd_max_offset,
		srg_bss_color_bitmap,
		srg_partial_bssid_bitmap,
	};
};

// 0xd9 - Spatial Reuse Report
// Wi-Fi EasyMesh
decoder[0xd9] = (buf, end) => {
	if (buf.pos() + 37 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	const bitfield = buf.get('B');
	const partial_bss_color = ((bitfield & 0b01000000) == 0b01000000);
	const bss_color = bitfield & 0b00111111;

	const bitfield2 = buf.get('B');
	const hesiga_spatial_reuse_value15_allowed = ((bitfield2 & 0b00010000) == 0b00010000);
	const srg_information_valid = ((bitfield2 & 0b00001000) == 0b00001000);
	const non_srg_offset_valid = ((bitfield2 & 0b00000100) == 0b00000100);
	const psr_disallowed = ((bitfield2 & 0b00000001) == 0b00000001);

	const non_srg_obsspd_max_offset = buf.get('B');
	const srg_obsspd_min_offset = buf.get('B');
	const srg_obsspd_max_offset = buf.get('B');
	const srg_bss_color_bitmap = buf.get('!Q');
	const srg_partial_bssid_bitmap = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const used_neighbor_bss_colors = buf.get('!Q');

	return {
		radio_unique_identifier,
		partial_bss_color,
		bss_color,
		hesiga_spatial_reuse_value15_allowed,
		srg_information_valid,
		non_srg_offset_valid,
		psr_disallowed,
		non_srg_obsspd_max_offset,
		srg_obsspd_min_offset,
		srg_obsspd_max_offset,
		srg_bss_color_bitmap,
		srg_partial_bssid_bitmap,
		used_neighbor_bss_colors,
	};
};

// 0xda - Spatial Reuse Config Response
// Wi-Fi EasyMesh
decoder[0xda] = (buf, end) => {
	if (buf.pos() + 7 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const response_code = buf.get('B');

	if (!exists(defs.RESPONSE_CODE, response_code))
		return null;

	return {
		radio_unique_identifier,
		response_code,
		response_code_name: defs.RESPONSE_CODE[response_code],
	};
};

// 0xdb - QoS Management Policy
// Wi-Fi EasyMesh
decoder[0xdb] = (buf, end) => {
	if (buf.pos() + 22 > end)
		return null;

	const mscs_disallowed_sta_count = buf.get('B');
	const mscs_disallowed_sta = [];

	for (let h = 0; h < mscs_disallowed_sta_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const mscs_disallowed_sta_mac = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(mscs_disallowed_sta, mscs_disallowed_sta_mac);
	}

	const scs_disallowed_sta_count = buf.get('B');
	const scs_disallowed_sta = [];

	for (let h = 0; h < scs_disallowed_sta_count; h++) {
		if (buf.pos() + 6 > end)
			return null;

		const scs_disallowed_sta_mac = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

		push(scs_disallowed_sta, scs_disallowed_sta_mac);
	}

	return {
		mscs_disallowed_sta,
		scs_disallowed_sta,
	};
};

// 0xdc - QoS Management Descriptor
// Wi-Fi EasyMesh
decoder[0xdc] = (buf, end) => {
	if (buf.pos() + 14 > end)
		return null;

	const qmid = buf.get('!H');
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const client_mac = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const descriptor_element = buf.get('*');

	return {
		qmid,
		bssid,
		client_mac,
		descriptor_element,
	};
};

// 0xdd - Controller Capability
// Wi-Fi EasyMesh
decoder[0xdd] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const bitfield = buf.get('B');
	const ki_bmi_b_counter = ((bitfield & 0b10000000) == 0b10000000);

	return ki_bmi_b_counter;
};

// -----------------------------------------------------------------------------
// TLV EXTENDED ENCODER ROUTINES
// -----------------------------------------------------------------------------

export const extended_encoder = [];

// 0x0001 - AP Radio VBSS Capabilities
// Wi-Fi EasyMesh
extended_encoder[0x0001] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	if (type(tlv.fixed_bits_mask) != "string" || length(tlv.fixed_bits_mask) > 6)
		return null;

	if (type(tlv.fixed_bits_value) != "string" || length(tlv.fixed_bits_value) > 6)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', tlv.max_vbss);
	buf.put('B', 0
		| (tlv.vbsss_subtract << 7)
		| (tlv.vbssid_restrictions << 6)
		| (tlv.vbssid_match_mask_restrictions << 5)
		| (tlv.fixed_bits_restrictions << 4)
	);

	buf.put('6s', tlv.fixed_bits_mask);
	buf.put('6s', tlv.fixed_bits_value);

	return buf;
};

// 0x0002 - Virtual BSS Creation
// Wi-Fi EasyMesh
extended_encoder[0x0002] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	if (type(tlv.ssid) != "string" || length(tlv.ssid) > 0xffff)
		return null;

	if (type(tlv.pass) != "string" || length(tlv.pass) > 0xffff)
		return null;

	if (type(tlv.dpp_connector) != "string" || length(tlv.dpp_connector) > 0xffff)
		return null;

	const client_mac = hexdec(match(tlv.client_mac, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (client_mac == null)
		return null;

	if (type(tlv.key) != "string" || length(tlv.key) > 0xffff)
		return null;

	if (type(tlv.group_key) != "string" || length(tlv.group_key) > 0xffff)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('6s', bssid);
	buf.put('!H', length(tlv.ssid));
	buf.put('*', tlv.ssid);
	buf.put('!H', length(tlv.pass));
	buf.put('*', tlv.pass);
	buf.put('!H', length(tlv.dpp_connector));
	buf.put('*', tlv.dpp_connector);
	buf.put('6s', client_mac);
	buf.put('B', tlv.client_assoc);
	buf.put('!H', length(tlv.key));
	buf.put('*', tlv.key);
	buf.put('!Q', tlv.tx_packet_number);
	buf.put('!H', length(tlv.group_key));
	buf.put('*', tlv.group_key);
	buf.put('!Q', tlv.group_tx_packet_number);

	return buf;
};

// 0x0003 - Virtual BSS Destruction
// Wi-Fi EasyMesh
extended_encoder[0x0003] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('6s', bssid);
	buf.put('B', tlv.disassociate_client);

	return buf;
};

// 0x0004 - Virtual BSS Event
// Wi-Fi EasyMesh
extended_encoder[0x0004] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	const radio_unique_identifier = hexdec(match(tlv.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (radio_unique_identifier == null)
		return null;

	const bssid = hexdec(match(tlv.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

	if (bssid == null)
		return null;

	buf.put('6s', radio_unique_identifier);
	buf.put('B', tlv.success);
	buf.put('6s', bssid);

	return buf;
};

// 0x0005 - Client Security Context
// Wi-Fi EasyMesh
extended_encoder[0x0005] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	if (type(tlv.key) != "string" || length(tlv.key) > 0xffff)
		return null;

	if (type(tlv.group_key) != "string" || length(tlv.group_key) > 0xffff)
		return null;

	buf.put('B', 0
		| (tlv.client_connected << 7)
	);

	buf.put('!H', length(tlv.key));
	buf.put('*', tlv.key);
	buf.put('!Q', tlv.tx_packet_number);
	buf.put('!H', length(tlv.group_key));
	buf.put('*', tlv.group_key);
	buf.put('!Q', tlv.group_tx_packet_number);

	return buf;
};

// 0x0006 - Trigger Channel Switch Announcement
// Wi-Fi EasyMesh
extended_encoder[0x0006] = (buf, tlv) => {
	if (type(tlv) != "object")
		return null;

	buf.put('B', tlv.csa_channel);
	buf.put('B', tlv.op_class);

	return buf;
};

// 0x0007 - VBSS Configuration Report
// Wi-Fi EasyMesh
extended_encoder[0x0007] = (buf, radios) => {
	if (type(radios) != "array" || length(radios) > 0xff)
		return null;

	buf.put('B', length(radios));

	for (let item in radios) {
		if (type(item) != "object")
			return null;

		const radio_unique_identifier = hexdec(match(item.radio_unique_identifier, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

		if (radio_unique_identifier == null)
			return null;

		if (type(item.vbss) != "array" || length(item.vbss) > 0xff)
			return null;

		buf.put('6s', radio_unique_identifier);
		buf.put('B', length(item.vbss));

		for (let item2 in item.vbss) {
			if (type(item2) != "object")
				return null;

			const bssid = hexdec(match(item2.bssid, /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i)?.[0], ":");

			if (bssid == null)
				return null;

			if (type(item2.ssid) != "string" || length(item2.ssid) > 0xff)
				return null;

			buf.put('6s', bssid);
			buf.put('B', length(item2.ssid));
			buf.put('*', item2.ssid);
		}
	}

	return buf;
};

// -----------------------------------------------------------------------------
// TLV EXTENDED DECODER ROUTINES
// -----------------------------------------------------------------------------

export const extended_decoder = [];

// 0x0001 - AP Radio VBSS Capabilities
// Wi-Fi EasyMesh
extended_decoder[0x0001] = (buf, end) => {
	if (buf.pos() + 20 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const max_vbss = buf.get('B');

	const bitfield = buf.get('B');
	const vbsss_subtract = ((bitfield & 0b10000000) == 0b10000000);
	const vbssid_restrictions = ((bitfield & 0b01000000) == 0b01000000);
	const vbssid_match_mask_restrictions = ((bitfield & 0b00100000) == 0b00100000);
	const fixed_bits_restrictions = ((bitfield & 0b00010000) == 0b00010000);

	const fixed_bits_mask = buf.get(6);
	const fixed_bits_value = buf.get(6);

	return {
		radio_unique_identifier,
		max_vbss,
		vbsss_subtract,
		vbssid_restrictions,
		vbssid_match_mask_restrictions,
		fixed_bits_restrictions,
		fixed_bits_mask,
		fixed_bits_value,
	};
};

// 0x0002 - Virtual BSS Creation
// Wi-Fi EasyMesh
extended_decoder[0x0002] = (buf, end) => {
	if (buf.pos() + 45 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const ssid_length = buf.get('!H');

	if (buf.pos() + ssid_length > end)
		return null;

	const ssid = buf.get(ssid_length);
	const pass_length = buf.get('!H');

	if (buf.pos() + pass_length > end)
		return null;

	const pass = buf.get(pass_length);
	const dpp_connector_length = buf.get('!H');

	if (buf.pos() + dpp_connector_length > end)
		return null;

	const dpp_connector = buf.get(dpp_connector_length);
	const client_mac = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const client_assoc = buf.get('B');
	const key_length = buf.get('!H');

	if (buf.pos() + key_length > end)
		return null;

	const key = buf.get(key_length);
	const tx_packet_number = buf.get('!Q');
	const group_key_length = buf.get('!H');

	if (buf.pos() + group_key_length > end)
		return null;

	const group_key = buf.get(group_key_length);
	const group_tx_packet_number = buf.get('!Q');

	return {
		radio_unique_identifier,
		bssid,
		ssid,
		pass,
		dpp_connector,
		client_mac,
		client_assoc,
		key,
		tx_packet_number,
		group_key,
		group_tx_packet_number,
	};
};

// 0x0003 - Virtual BSS Destruction
// Wi-Fi EasyMesh
extended_decoder[0x0003] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const disassociate_client = buf.get('B');

	return {
		radio_unique_identifier,
		bssid,
		disassociate_client,
	};
};

// 0x0004 - Virtual BSS Event
// Wi-Fi EasyMesh
extended_decoder[0x0004] = (buf, end) => {
	if (buf.pos() + 13 > end)
		return null;

	const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
	const success = buf.get('B');
	const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));

	return {
		radio_unique_identifier,
		success,
		bssid,
	};
};

// 0x0005 - Client Security Context
// Wi-Fi EasyMesh
extended_decoder[0x0005] = (buf, end) => {
	if (buf.pos() + 21 > end)
		return null;

	const bitfield = buf.get('B');
	const client_connected = ((bitfield & 0b10000000) == 0b10000000);

	const key_length = buf.get('!H');

	if (buf.pos() + key_length > end)
		return null;

	const key = buf.get(key_length);
	const tx_packet_number = buf.get('!Q');
	const group_key_length = buf.get('!H');

	if (buf.pos() + group_key_length > end)
		return null;

	const group_key = buf.get(group_key_length);
	const group_tx_packet_number = buf.get('!Q');

	return {
		client_connected,
		key,
		tx_packet_number,
		group_key,
		group_tx_packet_number,
	};
};

// 0x0006 - Trigger Channel Switch Announcement
// Wi-Fi EasyMesh
extended_decoder[0x0006] = (buf, end) => {
	if (buf.pos() + 2 > end)
		return null;

	const csa_channel = buf.get('B');
	const op_class = buf.get('B');

	return {
		csa_channel,
		op_class,
	};
};

// 0x0007 - VBSS Configuration Report
// Wi-Fi EasyMesh
extended_decoder[0x0007] = (buf, end) => {
	if (buf.pos() + 1 > end)
		return null;

	const radios_count = buf.get('B');
	const radios = [];

	for (let h = 0; h < radios_count; h++) {
		if (buf.pos() + 7 > end)
			return null;

		const radio_unique_identifier = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
		const vbss_count = buf.get('B');
		const vbss = [];

		for (let i = 0; i < vbss_count; i++) {
			if (buf.pos() + 7 > end)
				return null;

			const bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...buf.read('6B'));
			const ssid_length = buf.get('B');

			if (buf.pos() + ssid_length > end)
				return null;

			const ssid = buf.get(ssid_length);

			push(vbss, {
				bssid,
				ssid,
			});
		}

		push(radios, {
			radio_unique_identifier,
			vbss,
		});
	}

	return radios;
};

