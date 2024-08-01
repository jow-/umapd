/*
 * Copyright (c) 2022 Jo-Philipp Wich <jo@mein.io>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

export default {
	IEEE1905_MULTICAST_MAC: '01:80:c2:00:00:13',
	LLDP_NEAREST_BRIDGE_MAC: '01:80:c2:00:00:0e',

	CMDU_F_LASTFRAG: 0b10000000,
	CMDU_F_ISRELAY: 0b01000000,

	MSG_TOPOLOGY_DISCOVERY: 0x0000,
	MSG_TOPOLOGY_NOTIFICATION: 0x0001,
	MSG_TOPOLOGY_QUERY: 0x0002,
	MSG_TOPOLOGY_RESPONSE: 0x0003,
	MSG_VENDOR_SPECIFIC: 0x0004,
	MSG_LINK_METRIC_QUERY: 0x0005,
	MSG_LINK_METRIC_RESPONSE: 0x0006,
	MSG_AP_AUTOCONFIG_SEARCH: 0x0007,
	MSG_AP_AUTOCONFIG_RESPONSE: 0x0008,
	MSG_AP_AUTOCONFIG_WSC: 0x0009,
	MSG_AP_AUTOCONFIG_RENEW: 0x000A,
	MSG_PUSHBUTTON_NOTIFY: 0x000B,
	MSG_PUSHBUTTON_JOIN: 0x000C,
	MSG_HIGHER_LAYER_QUERY: 0x000D,
	MSG_HIGHER_LAYER_RESPONSE: 0x000E,
	MSG_IF_POWER_CHANGE_QUERY: 0x000F,
	MSG_IF_POWER_CHANGE_RESPONSE: 0x0010,
	MSG_GENERIC_PHY_QUERY: 0x0011,
	MSG_GENERIC_PHY_RESPONSE: 0x0012,
	MSG_COMBINED_INFRASTRUCTURE_METRICS: 0x8013,

	TLV_END_OF_MESSAGE: 0x0000,
	TLV_AL_MAC_ADDRESS: 0x0001,
	TLV_MAC_ADDRESS: 0x0002,
	TLV_DEVICE_INFORMATION: 0x0003,
	TLV_DEVICE_BRIDGING_CAPABILITY: 0x0004,
	TLV_NON1905_NEIGHBOR_DEVICES: 0x0006,
	TLV_IEEE1905_NEIGHBOR_DEVICES: 0x0007,
	TLV_LINK_METRIC_QUERY: 0x0008,
	TLV_LINK_METRIC_TX: 0x0009,
	TLV_LINK_METRIC_RX: 0x000a,
	TLV_VENDOR_SPECIFIC: 0x000b,
	TLV_LINK_METRIC_RESULT: 0x000c,
	TLV_SEARCHEDROLE: 0x000d,
	TLV_AUTOCONFIGFREQBAND: 0x000e,
	TLV_SUPPORTEDROLE: 0x000f,
	TLV_SUPPORTEDFREQBAND: 0x0010,
	TLV_WSC: 0x0011,
	TLV_PUSH_BUTTON_EVENT_NOTIFICATION: 0x0012,
	TLV_PUSH_BUTTON_JOIN_NOTIFICATION: 0x0013,
	TLV_GENERIC_PHY_DEVICE_INFORMATION: 0x0014,
	TLV_DEVICE_IDENTIFICATION: 0x0015,
	TLV_CONTROL_URL: 0x0016,
	TLV_IPV4: 0x0017,
	TLV_IPV6: 0x0018,
	TLV_PUSH_BUTTON_GENERIC_PHY_EVENT_NOTIFICATION: 0x0019,
	TLV_1905_PROFILE_VERSION: 0x001a,
	TLV_POWER_OFF_INTERFACE: 0x001b,
	TLV_INTERFACE_POWER_CHANGE_INFORMATION: 0x001c,
	TLV_INTERFACE_POWER_CHANGE_STATUS: 0x001d,
	TLV_L2_NEIGHBOR_DEVICE: 0x001e,
	TLV_SUPPORTEDSERVICE: 0x0080,
	TLV_SEARCHEDSERVICE: 0x0081,
	TLV_AP_RADIO_IDENTIFIER: 0x0082,
	TLV_AP_OPERATIONAL_BSS: 0x0083,
	TLV_ASSOCIATED_CLIENTS: 0x0084,
	TLV_AP_METRICS: 0x0094,
	TLV_MULTI_AP_PROFILE: 0x00b3,
	TLV_PROFILE_2_AP_CAPABILITY: 0x00b4,

	ASSOCIATION_ALLOWANCE_STATUS: {
		[0x00]: 'No more associations allowed',
		[0x01]: 'Associations allowed',
	},

	CAC_COMPLETION_STATUS: {
		[0x00]: 'Successful',
		[0x01]: 'Radar detected',
		[0x02]: 'CAC not supported as requested (capability mismatch)',
		[0x03]: 'Radio too busy to perform CAC',
		[0x04]: 'Request was considered to be non-conformant to regulations in the country in which the Multi-AP Agent is operating',
		[0x05]: 'Other error',
	},

	CAC_METHOD_SUPPORTED: {
		[0x00]: 'Continuous CAC',
		[0x01]: 'Continuous with dedicated radio',
		[0x02]: 'MIMO dimension reduced',
		[0x03]: 'Time sliced CAC',
	},

	CHANNEL_SELECTION_RESPONSE_CODE: {
		[0x00]: 'Accept',
		[0x01]: 'Decline because request violates current preferences which have changed since last reported',
		[0x02]: 'Decline because request violates most recently reported preferences',
		[0x03]: 'Decline because request would prevent operation of a currently operating backhaul link (where backhaul STA and BSS share a radio)',
	},

	IEEE1905_PROFILE_VERSIONS: {
		[0x00]: '1905.1',
		[0x01]: '1905.1a'
	},

	IEEE80211_BANDS: {
		[0x00]: '2.4 GHz',
		[0x01]: '5 GHz',
		[0x02]: '60 GHz'
	},

	IEEE80211_ROLES: {
		[0b00000000]: 'AP',
		[0b01000000]: 'STA',
		[0b10000000]: 'Wi-Fi P2P Client',
		[0b10010000]: 'Wi-Fi P2P Group Owner',
		[0b10100000]: '802.11adPCP'
	},

	IPV4ADDR_TYPES: {
		[0x00]: 'Unknown',
		[0x01]: 'DHCP',
		[0x02]: 'Static',
		[0x03]: 'Auto-IP'
	},

	IPV6ADDR_TYPES: {
		[0x00]: 'Unknown',
		[0x01]: 'DHCP',
		[0x02]: 'Static',
		[0x03]: 'SLAAC'
	},

	LINK_METRIC_RESULT_CODES: {
		[0x00]: 'Invalid neighbor'
	},

	MEDIA_TYPES: {
		[0x0000]: 'IEEE 802.3u fast Ethernet',
		[0x0001]: 'IEEE 802.3ab gigabit Ethernet',
		[0x0100]: 'IEEE 802.11b (2.4 GHz)',

		[0x0101]: 'IEEE 802.11g (2.4 GHz)',
		[0x0102]: 'IEEE 802.11a (5 GHz)',
		[0x0103]: 'IEEE 802.11n (2.4 GHz)',
		[0x0104]: 'IEEE 802.11n (5 GHz)',
		[0x0105]: 'IEEE 802.11ac (5 GHz)',
		[0x0106]: 'IEEE 802.11ad (60 GHz)',
		[0x0107]: 'IEEE 802.11ax (2.4 GHz)',
		[0x0108]: 'IEEE 802.11ax (5 GHz)',

		[0x0200]: 'IEEE 1901 wavelet',
		[0x0201]: 'IEEE 1901 FFT',

		[0x0300]: 'MoCA v1.1'
	},

	MULTI_AP_PROFILES: {
		[0x00]: 'Reserved',
		[0x01]: 'Multi-AP Profile 1',
		[0x02]: 'Multi-AP Profile 2',
		[0x03]: 'Multi-AP Profile 3'
	},

	POWER_CHANGE_RESULT_CODES: {
		[0x00]: 'Request completed',
		[0x01]: 'No change made',
		[0x02]: 'Alternative change made'
	},

	POWER_STATES: {
		[0x00]: 'PWR_OFF',
		[0x01]: 'PWR_ON',
		[0x02]: 'PWR_SAVE'
	},

	PROFILE_2_BYTE_COUNTER_UNIT: {
		[0x00]: 'bytes',
		[0x01]: 'kibibytes',
		[0x02]: 'mebibytes'
	},

	REASON_CODE: {
		[0x01]: 'STA associated with a BSS operated by the Multi-AP Agent.',
		[0x02]: 'STA not associated with any BSS operated by the Multi-AP Agent.',
		[0x03]: 'Client capability report unspecified failure',
		[0x04]: 'Backhaul steering request rejected because the backhaul STA cannot operate on the channel specified.',
		[0x05]: 'Backhaul steering request rejected because the target BSS signal is too weak or not found.',
		[0x06]: 'Backhaul steering request authentication or association Rejected by the target BSS.',
	},

	REASON_CODES: {
		[0x00]: 'SUCCESS',
		[0x01]: 'UNMATCHED_MAC_ADDRESS',
		[0x02]: 'UNSUPPORTED_PWR_STATE',
		[0x03]: 'UNAVAILABLE_POWER_STATE',
		[0x04]: 'NBR_OF_FWD_RULE_EXCEEDED',
		[0x05]: 'INVALID_RULE_ID',
		[0x06]: 'DUPLICATE_CLASSIFICATION_SET',
		[0x07]: 'UNMATCHED_NEIGHBOR_MAC_ADDRESS',
		[0x10]: 'FAILURE'
	},

	RESPONSE_CODE: {
		[0x00]: 'Accept',
		[0x01]: 'Decline because radio does not support requested configuration.',
	},

	RESULT_CODE: {
		[0x00]: 'Success',
		[0x01]: 'Failure',
	},

	SCAN_IMPACT: {
		[0x00]: 'No impact (independent radio is available for scanning that is not used for Fronthaul or backhaul)',
		[0x01]: 'Reduced number of spatial streams',
		[0x02]: 'Time slicing impairment (Radio may go off channel for a series of short intervals)',
		[0x03]: 'Radio unavailable for >= 2 seconds)',
	},

	SEARCHED_ROLES: {
		[0x00]: 'Registrar'
	},

	SEARCHED_SERVICES: {
		[0x00]: 'Multi-AP Controller'
	},

	STEERING_POLICY: {
		[0x00]: 'Agent Initiated Steering Disallowed',
		[0x01]: 'Agent Initiated RCPI-based Steering Mandated',
		[0x02]: 'Agent Initiated RCPI-based Steering Allowed',
	},

	SUPPORTED_SERVICE: {
		[0x00]: 'Multi-AP Controller',
		[0x01]: 'Multi-AP Agent',
	},

	SUPPORTED_SERVICES: {
		[0x00]: 'Multi-AP Controller',
		[0x01]: 'Multi-AP Agent'
	},

	TUNNELED_PROTOCOL_TYPE: {
		[0x00]: 'Association Request',
		[0x01]: 'Re-Association Request',
		[0x02]: 'BTM Query',
		[0x03]: 'WNM Request',
		[0x04]: 'ANQP request for Neighbor Report',
		[0x05]: 'DSCP Policy Query',
		[0x06]: 'DSCP Policy Response',
	},

	getCMDUTypeName: function(type) {
		for (let k, v in this)
			if (index(k, 'MSG_') == 0 && v == type)
				return substr(k, 4);
	},

	getTLVTypeName: function(type) {
		for (let k, v in this)
			if (index(k, 'TLV_') == 0 && v == type)
				return substr(k, 4);
	}
};
