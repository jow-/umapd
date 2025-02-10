/*
 * Copyright (c) 2024 Jo-Philipp Wich <jo@mein.io>.
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

import * as uloop from 'uloop';

import utils from 'umap.utils';
import model from 'umap.model';
import cmdu from 'umap.cmdu';
import defs from 'umap.defs';
import log from 'umap.log';

import * as wsc from 'umap.wsc';
import * as wconst from 'umap.wireless';
import configuration from 'umap.configuration';


const MAX_RETRIES = 5;

const IAgentSession = {
	state: 'init',
	retryCount: 0,
	lastActionTime: 0,
	controller: null,
	radio: null,
	key: null,
	m1: null,
	m2: null,

	isTimerExpired: function (timeoutSeconds) {
		return (time() - this.lastActionTime) > timeoutSeconds;
	},

	debug: function (msg) {
		log.debug(`autoconf: radio ${this.radio.address}: ${msg}`);
	},

	info: function (msg) {
		log.info(`autoconf: radio ${this.radio.address}: ${msg}`);
	},

	warn: function (msg) {
		log.warn(`autoconf: radio ${this.radio.address}: ${msg}`);
	},

	error: function (msg) {
		log.error(`autoconf: radio ${this.radio.address}: ${msg}`);
	},

	transitionState: function (new_state) {
		this.debug(`transition state ${this.state} to ${new_state}`);

		this.state = new_state;
		this.retryCount = 0;
		this.lastActionTime = 0;

		while (length(this.midsInFlight))
			pop(this.midsInFlight);
	},

	sendApAutoconfigurationSearch: function () {
		this.debug(`sending AP Auto-Configuration search request`);

		let msg = cmdu.create(defs.MSG_AP_AUTOCONFIGURATION_SEARCH);

		msg.add_tlv(defs.TLV_AL_MAC_ADDRESS, model.address);
		msg.add_tlv(defs.TLV_SEARCHED_ROLE, 0x00); // Registrar

		msg.add_tlv(defs.TLV_SUPPORTED_SERVICE, [0x01]); // Multi-AP Agent
		msg.add_tlv(defs.TLV_SEARCHED_SERVICE, [0x00]); // Multi-AP Controller
		msg.add_tlv(defs.TLV_MULTI_AP_PROFILE, 0x03); // Multi-AP Profile 3

		switch (this.radio.band) {
			case wconst.WPS_RF_2GHZ: msg.add_tlv(defs.TLV_AUTOCONFIG_FREQUENCY_BAND, 0x00); break;
			case wconst.WPS_RF_5GHZ: msg.add_tlv(defs.TLV_AUTOCONFIG_FREQUENCY_BAND, 0x01); break;
			case wconst.WPS_RF_60GHZ: msg.add_tlv(defs.TLV_AUTOCONFIG_FREQUENCY_BAND, 0x02); break;

			// FIXME: IEEE 1905.1 does not define a 6G band, send 5GHz for now
			case wconst.WPS_RF_6GHZ: msg.add_tlv(defs.TLV_AUTOCONFIG_FREQUENCY_BAND, 0x01); break;
		}

		push(this.midsInFlight, msg.mid);

		for (let i1905lif in model.getLocalInterfaces())
			msg.send(i1905lif.i1905sock, model.address, defs.IEEE1905_MULTICAST_MAC, defs.CMDU_F_ISRELAY);
	},

	sendApAutoconfigurationWscM1: function () {
		this.debug(`sending AP Auto-Configuration WSC M1`);

		let msg = cmdu.create(defs.MSG_AP_AUTOCONFIGURATION_WSC);
		let res = wsc.wscBuildM1(this.radio);

		this.m1 = res[0];
		this.m2 = null;
		this.key = res[1];

		msg.add_tlv(defs.TLV_AP_RADIO_BASIC_CAPABILITIES, this.radio.getBasicCapabilities());
		msg.add_tlv(defs.TLV_WSC, this.m1);
		msg.add_tlv(defs.TLV_PROFILE_2_AP_CAPABILITY, {
			byte_counter_unit: 0x00, // byte counter unit is bytes
			supports_prioritization: false,
			max_prioritization_rules: 0,
			supports_dpp_onboarding: false,
			supports_traffic_separation: false
		});
		msg.add_tlv(defs.TLV_AP_RADIO_ADVANCED_CAPABILITIES, {
			radio_unique_identifier: this.radio.address,
			combined_front_back: true,
			combined_profile1_profile2: true,
			mscs: false,
			scs: false,
			qos_map: false,
			dscp_policy: false
		});

		push(this.midsInFlight, msg.mid);

		msg.send(this.controller.i1905lif.i1905sock,
			model.address, this.controller.address);
	},

	step: function () {
		switch (this.state) {
			case 'init':
				this.transitionState('search_controller');
				break;

			case 'search_controller':
				if (this.retryCount === 0 || this.isTimerExpired(60)) {  // 1 minute between attempts
					this.sendApAutoconfigurationSearch();
					this.retryCount++;
					this.lastActionTime = time();
				}

				if (this.retryCount >= MAX_RETRIES)
					this.transitionState('backoff');

				break;

			case 'backoff':
				if (this.isTimerExpired(300)) {  // 5 minutes backoff
					this.retryCount = 0;
					this.transitionState('search_controller');
				}

				break;

			case 'config_request':
				if (this.retryCount === 0 || this.isTimerExpired(30)) {  // 30 seconds between attempts
					this.sendApAutoconfigurationWscM1();
					this.retryCount++;
					this.lastActionTime = time();
				}

				if (this.retryCount >= MAX_RETRIES)
					this.transitionState('search_controller');

				break;

			case 'config_apply':
				const bssConfigs = [];

				for (let m2 in this.m2) {
					const settings = wsc.wscProcessM2(this.key, this.m1, m2);

					if (!settings) {
						this.error('failed to process M2');
						this.transitionState('config_request');
						return;
					}

					this.info(`got settings: ${settings}`);
					push(bssConfigs, settings);
				}

				uloop.process('/usr/libexec/umap/wifi-apply',
					[sprintf('%J', bssConfigs)],
					{
						RADIO: this.radio.config,
						PHY: this.radio.phyname,
						NETWORK: 'easymesh' // FIXME: derive from local interface
					},
					function (exitcode) {
						log.debug(`wifi-apply exited with code ${exitcode}`);
					});

				this.transitionState('idle');
				break;
		}
	},

	handle_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		if (!(msg.mid in this.midsInFlight))
			return false;

		if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_RESPONSE) {
			this.debug(`received AP Auto-Configuration response`);

			if (this.state != 'search_controller')
				return this.warn(`received controller advertisement while not in search state`);

			if (!length(filter(msg.get_tlv(defs.TLV_SUPPORTED_SERVICE), e => e.supported_service_name == 'Multi-AP Controller')))
				return this.warn(`ignoring response not advertising Multi-AP Controller service`);

			if (msg.get_tlv(defs.TLV_SUPPORTED_ROLE)?.role_name != 'Registrar')
				return this.warn(`ignoring response not advertising Registrar role`);

			const controllerProfile = msg.get_tlv(defs.TLV_MULTI_AP_PROFILE)?.profile;

			if (!(controllerProfile in [0x01, 0x02, 0x03]))
				return this.warn(`ignoring response advertising unsupported Multi-AP profile`);

			this.controller = {
				address: srcmac,
				profile: controllerProfile,
				i1905lif: i1905lif
			};

			this.transitionState('config_request');
			this.step();
		}
		else if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_WSC) {
			log.debug(`autoconf: received AP Auto-Configuration WSC message`);

			if (this.state != 'config_request')
				return this.warn(`received AP Auto-Configuration WSC message while not in config_request state`);

			//			let sender = model.lookupDevice(srcmac);
			//
			//			if (!sender)
			//				return this.warn(`received AP Auto-Configuration WSC message from unknown device ${srcmac}`);

			const wscFrames = msg.get_tlvs(defs.TLV_WSC);

			if (length(wscFrames) == 0)
				return this.warn(`received AP Auto-Configuration WSC message without WSC TLV`);

			this.m2 = [];

			for (let wscFrame in wscFrames) {
				const wscType = wsc.wscGetType(wscFrame);

				if (wscType != 2)
					return this.warn(`received AP Auto-Configuration WSC message with unxpected type (${wscType ?? 'unknown'})`);

				push(this.m2, wscFrame);
			}

			this.transitionState('config_apply');
			this.step();
		}

		return true;
	}
};

const IProtoAutoConf = {
	init: function () {
		const sessions = this.sessions;

		// No scheduled work to do in controller mode
		if (model.isController)
			return configuration.parseBSSConfigurations();

		for (let radio in model.getRadios()) {
			// Let first session trigger controller discovery, start others in
			// idle state and nudge them once we found a controller
			push(sessions, proto({
				state: 'init',
				radio: radio,
				midsInFlight: []
			}, IAgentSession));
		}

		uloop.timer(1000, function () {
			this.set(1000);

			for (let session in sessions)
				session.step();
		});
	},

	handle_controller_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_SEARCH) {
			log.debug(`autoconf: received AP Auto-Configuration search request`);

			let sender = model.lookupDevice(srcmac);

			if (!sender)
				return log.warn(`autoconf: ignoring search request from unknown peer ${srcmac}`);

			if (msg.get_tlv(defs.TLV_SEARCHED_ROLE)?.role_name != 'Registrar')
				return log.warn(`autoconf: ignoring search request not searching for Registrar role`);

			const searchesController = filter(msg.get_tlv(defs.TLV_SEARCHED_SERVICE),
				s => s.searched_service_name == 'Multi-AP Controller');

			if (!length(searchesController))
				return log.warn(`autoconf: ignoring search request not searching for Controller service`);

			const searchesBand = msg.get_tlv(defs.TLV_AUTOCONFIG_FREQUENCY_BAND);

			if (!searchesBand)
				return log.warn(`autoconf: ignoring search request with missing frequency band`);

			//if (!searchesBand.frequency_band_name in config)
			//	return log.warn(`autoconf: no suitable configuration for requested band ${searchesBand.frequency_band_name}`);

			log.debug(`autoconf: sending AP Auto-Configuration search reply`);

			let reply = cmdu.create(defs.MSG_AP_AUTOCONFIGURATION_RESPONSE, msg.mid);

			reply.add_tlv(defs.TLV_SUPPORTED_ROLE, 0x00); // Registrar
			reply.add_tlv(defs.TLV_SUPPORTED_FREQUENCY_BAND, searchesBand.frequency_band);
			reply.add_tlv(defs.TLV_SUPPORTED_SERVICE, [0x00]); // Controller

			reply.add_tlv(defs.TLV_IEEE1905_LAYER_SECURITY_CAPABILITY, {
				onboarding_protocol: 0x00,  // DPP
				mic_algorithm: 0x00,        // HMAC-SHA256
				encryption_algorithm: 0x00, // AES-SIV
			});

			reply.add_tlv(defs.TLV_MULTI_AP_PROFILE, 0x03); // Multi-AP Profile 3

			// TODO: DPP Chirp

			reply.add_tlv(defs.TLV_CONTROLLER_CAPABILITY, true);

			//reply.send(i1905lif.i1905sock, dstmac, srcmac);
			reply.send(i1905lif.i1905sock, model.address, sender.al_address);
		}
		else if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_WSC) {
			log.debug(`autoconf: received AP Auto-Configuration WSC message`);

			let sender = model.lookupDevice(srcmac);

			if (!sender)
				return log.warn(`autoconf: received AP Auto-Configuration WSC message from unknown device ${srcmac}`);

			const radioCapabilities = msg.get_tlv(defs.TLV_AP_RADIO_BASIC_CAPABILITIES);

			if (radioCapabilities == null)
				return log.warn(`autoconf: received AP Auto-Configuration WSC message without radio capabilities`);

			const wscFrame = msg.get_tlv(defs.TLV_WSC);

			if (wscFrame == null)
				return log.warn(`autoconf: received AP Auto-Configuration WSC message without WSC TLV`);

			const wscType = wsc.wscGetType(wscFrame);

			if (wscType != 1)
				return log.warn(`autoconf: received AP Auto-Configuration WSC message with unxpected type (${wscType ?? 'unknown'})`);

			const wscDetails = wsc.wscProcessM1(wscFrame);
			const desiredBSSes = configuration.selectBSSConfigurations(
				wscDetails.supported_bands,
				wscDetails.supported_authentication_types,
				wscDetails.supported_encryption_types);

			if (length(desiredBSSes) == 0) {
				push(desiredBSSes, {
					auth_mask: wconst.WPS_AUTH_OPEN,
					cipher_mask: wconst.WPS_ENCR_NONE,
					band_mask: wconst.WPS_RF_2GHZ,
					bssid: '00:00:00:00:00:00',
					ssid: '',
					network_key: '',
					multi_ap: {
						tear_down: true
					}
				})
			}

			let reply = cmdu.create(defs.MSG_AP_AUTOCONFIGURATION_WSC, msg.mid);

			reply.add_tlv(defs.TLV_AP_RADIO_IDENTIFIER, radioCapabilities.radio_unique_identifier);

			let bssid = radioCapabilities.radio_unique_identifier;

			for (let i, desiredBSS in desiredBSSes) {
				const m2 = wsc.wscBuildM2(wscFrame, {
					authentication_types: desiredBSS.auth_mask,
					encryption_types: desiredBSS.cipher_mask,
					band: desiredBSS.band_mask,
					bssid: utils.ether_increment(bssid, i),
					ssid: desiredBSS.ssid,
					network_key: desiredBSS.key ?? '',
					multi_ap: {
						is_backhaul_sta: false,
						is_backhaul_bss: (desiredBSS.type == 'backhaul'),
						is_fronthaul_bss: (desiredBSS.type == 'fronthaul'),
						tear_down: false,
						multi_ap_profile1_backhaul_sta_assoc_dissallowed: false,
						multi_ap_profile2_backhaul_sta_assoc_dissallowed: false
					},
				});

				reply.add_tlv(defs.TLV_WSC, m2);
			}

			reply.send(i1905lif.i1905sock, model.address, sender.al_address);
		}
	},

	handle_agent_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		for (let session in this.sessions)
			if (session.handle_cmdu(i1905lif, dstmac, srcmac, msg))
				return true;

		//log.debug(`autoconf: discarding unexpected CMDU ${msg.mid}`);

		return false;
	},

	handle_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		if (model.isController)
			return this.handle_controller_cmdu(i1905lif, dstmac, srcmac, msg);
		else
			return this.handle_agent_cmdu(i1905lif, dstmac, srcmac, msg);
	}
};

export default proto({
	sessions: []
}, IProtoAutoConf);
