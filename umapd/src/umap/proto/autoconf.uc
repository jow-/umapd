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

import { process, timer } from 'uloop';

import utils from 'umap.utils';
import model from 'umap.model';
import cmdu from 'umap.cmdu';
import defs from 'umap.defs';
import ubus from 'umap.ubus';
import log from 'umap.log';

import * as wsc from 'umap.wsc';
import * as wconst from 'umap.wireless';
import configuration from 'umap.configuration';


const callbacks = {};
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
		return true;
	},

	info: function (msg) {
		log.info(`autoconf: radio ${this.radio.address}: ${msg}`);
		return true;
	},

	warn: function (msg) {
		log.warn(`autoconf: radio ${this.radio.address}: ${msg}`);
		return true;
	},

	error: function (msg) {
		log.error(`autoconf: radio ${this.radio.address}: ${msg}`);
		return true;
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

		msg.add_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS, model.address);
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

		model.sendMulticast(msg, defs.IEEE1905_MULTICAST_MAC, defs.CMDU_F_ISRELAY);
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

		model.sendController(msg);
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

				process('/usr/libexec/umap/wifi-apply',
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
		if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_RESPONSE) {
			// Ignore autoconf responses not belonging to our pending requests
			if (!(msg.mid in this.midsInFlight)) {
				this.debug(`unexpected AP Auto-Configuration reponse`);
				return false;
			}

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

			if (!model.networkController) {
				model.networkController = {
					address: srcmac,
					profile: controllerProfile,
					i1905lif: i1905lif
				};
			}
			else if (srcmac != model.networkController.address) {
				return this.warn(`ignoring response from unexpected device ${al_mac}, expecting ${model.networkController.address}`);
			}

			this.transitionState('config_request');
			this.step();

			return true;
		}
		else if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_WSC) {
			if (srcmac != model.networkController.address)
				return this.warn(`received WSC message from unexpected address ${srcmac}, expected ${model.networkController.address}`);

			const radio_id = msg.get_tlv(defs.TLV_AP_RADIO_IDENTIFIER);

			if (radio_id != this.radio.address) {
				this.debug(`ignoring WSC message for different radio ${radio_id}`);
				return false;
			}

			if (this.state != 'config_request')
				return this.warn(`received WSC message while not in config request state`);

			const wscFrames = msg.get_tlvs(defs.TLV_WSC);

			if (length(wscFrames) == 0)
				return this.warn(`received WSC message without WSC TLV`);

			this.m2 = [];

			for (let wscFrame in wscFrames) {
				const wscType = wsc.wscGetType(wscFrame);

				if (wscType != 2)
					return this.warn(`received WSC message with unxpected type (${wscType ?? 'unknown'})`);

				push(this.m2, wscFrame);
			}

			this.debug(`autoconf: received WSC reply`);

			this.transitionState('config_apply');
			this.step();

			return true;
		}
		else if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_RENEW) {
			if (this.state != 'idle') {
				this.debug(`ignoring renew request while not idle`);
				return false;
			}

			const al_mac = msg.get_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS);

			if (!al_mac)
				return this.warn(`ignoring incomplete renew request`);

			if (al_mac != model.networkController.address)
				return this.warn(`ignoring renew request from unexpected device ${al_mac}, expecting ${model.networkController.address}`);

			const self = this;
			timer(500, () => {
				self.transitionState('config_request');
				self.step();
			});
		}

		return false;
	}
};

const IProtoAutoConf = {
	init: function () {
		if (model.isController) {
			configuration.reload();
			ubus.register('renew_ap_autoconfig', {}, this.renew_ap_autoconfig);
		}
		else {
			const sessions = this.sessions;

			timer(1000, function () {
				this.set(1000);

				for (let session in sessions)
					session.step();
			});
		}
	},

	renew_ap_autoconfig: function (req) {
		if (!model.isController)
			return req.reply(null, 8 /* UBUS_STATUS_NOT_SUPPORTED */);

		configuration.reload();

		const i1905self = model.getLocalDevice();

		for (let i1905dev in model.getDevices()) {
			if (i1905dev === i1905self)
				continue;

			const renew = cmdu.create(defs.MSG_AP_AUTOCONFIGURATION_RENEW);

			renew.add_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS, model.address);
			renew.add_tlv(defs.TLV_SUPPORTED_ROLE, 0x00 /* Registrar */);

			/* IEEE 1905.1-2013 Section 10.1.3 states that the autoconfig
			 * process should be repeated for each band supported by the
			 * registrar.
			 *
			 * Wi-Fi EasyMesh v5.0 Section 7.1 on the other states that a map
			 * agent shall proceed with sending WSC M1 for each of its radios
			 * irrespective of the value specified in the SupportedFreqBand.
			 *
			 * Since map agents thus effectively ignore the indicated
			 * supported band, don't re-send for each band and simply
			 * hardcoded 2.4GHz */
			renew.add_tlv(defs.TLV_SUPPORTED_FREQUENCY_BAND, 0x00 /* 2.4GHz */);

			const dstmac = i1905dev.al_address;

			callbacks[dstmac] = {
				try: 0,
				dstmac: dstmac,
				timeout: timer(1000, () => {
					const s = callbacks[dstmac];

					if (s.try >= 3) {
						log.warn(`autoconf: device ${s.dstmac} did not acknowledge reconfig - connection lost?`);
						delete callbacks[s.dstmac];
						return;
					}

					log.warn(`autoconf: no WSC M1 from ${s.dstmac} for renew CMDU [${renew.mid}], retrying`);

					model.sendMulticast(renew, s.dstmac, cmdu.CMDU_F_ISRELAY);

					this.set(1000);
					s.try++;
				})
			};

			model.sendMulticast(renew, i1905dev.al_address, cmdu.CMDU_F_ISRELAY);
		}

		return req.reply({ success: true });
	},

	start_autoconfiguration: function () {
		if (model.isController)
			return;

		if (length(this.sessions))
			return;

		for (let radio in model.getRadios()) {
			push(this.sessions, proto({
				state: 'init',
				radio: radio,
				midsInFlight: []
			}, IAgentSession));
		}
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

			return true;
		}
		else if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_WSC) {
			log.debug(`autoconf: received AP Auto-Configuration WSC message`);

			let sender = model.lookupDevice(srcmac);

			if (!sender)
				return log.warn(`autoconf: received AP Auto-Configuration WSC message from unknown device ${srcmac}`);

			if (!sender.haveStaCapabilities)
				return log.warn(`autoconf: ignoring request from device ${srcmac} still in topology exchange`);

			const radioCapabilities = msg.get_tlv(defs.TLV_AP_RADIO_BASIC_CAPABILITIES);

			if (radioCapabilities == null)
				return log.warn(`autoconf: received AP Auto-Configuration WSC message without radio capabilities`);

			const wscFrame = msg.get_tlv(defs.TLV_WSC);

			if (wscFrame == null)
				return log.warn(`autoconf: received AP Auto-Configuration WSC message without WSC TLV`);

			const wscType = wsc.wscGetType(wscFrame);

			if (wscType != 1)
				return log.warn(`autoconf: received AP Auto-Configuration WSC message with unxpected type (${wscType ?? 'unknown'})`);

			const s = callbacks[srcmac];

			if (s) {
				log.info(`autoconfig: device ${s.dstmac} acknowledged renew request`);

				s.timeout.cancel();
				delete callbacks[srcmac];
			}

			const wscDetails = wsc.wscProcessM1(wscFrame);
			const desiredBSSes = configuration.selectBSSConfigurations(
				wscDetails.supported_bands,
				wscDetails.supported_authentication_types,
				wscDetails.supported_encryption_types);

			/* When the sending device announced backhaul station capability,
			 * include configuration for the backhaul STA connection as well.
			 * Synthesize the STA configuration by mirroring the (first)
			 * backhaul BSS configuration and simply flipping the type. */
			if (sender.getBackhaulSTACapability(radioCapabilities.radio_unique_identifier)) {
				/* When this is the first device we're onboarding, don't include
				 * backhaul station credentials as it will cause the agent to
				 * spawn a station having nothing to connect to, inhibiting the
				 * launch of AP BSSes on the same radio. */
				if (!sender.isFirstDevice()) {
					for (let bss in desiredBSSes) {
						if (bss.type == 'backhaul') {
							unshift(desiredBSSes, { ...bss, type: 'station' });
							break;
						}
					}
				}
			}

			if (length(desiredBSSes) == 0) {
				push(desiredBSSes, {
					type: 'disable',
					auth_mask: wconst.WPS_AUTH_OPEN,
					cipher_mask: wconst.WPS_ENCR_NONE,
					band_mask: wconst.WPS_RF_2GHZ,
					bssid: '00:00:00:00:00:00',
					ssid: '',
					network_key: '',
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
					bssid: (desiredBSS.type in ['fronthaul', 'backhaul'])
						? utils.ether_increment(bssid, i) : '00:00:00:00:00:00',
					ssid: desiredBSS.ssid,
					network_key: desiredBSS.key ?? '',
					multi_ap: {
						is_backhaul_sta: (desiredBSS.type == 'station'),
						is_backhaul_bss: (desiredBSS.type == 'backhaul'),
						is_fronthaul_bss: (desiredBSS.type == 'fronthaul'),
						tear_down: (desiredBSS.type == 'disable'),
						multi_ap_profile1_backhaul_sta_assoc_dissallowed: false,
						multi_ap_profile2_backhaul_sta_assoc_dissallowed: false
					},
				});

				reply.add_tlv(defs.TLV_WSC, m2);
			}

			reply.send(i1905lif.i1905sock, model.address, sender.al_address);

			return true;
		}
	},

	handle_agent_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		for (let session in this.sessions)
			if (session.handle_cmdu(i1905lif, dstmac, srcmac, msg))
				return true;

		// Consider renew requests to be handled
		if (msg.type == defs.MSG_AP_AUTOCONFIGURATION_RENEW)
			return true;

		return false;
	},

	handle_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		// Ignore CMDUs not destined to us
		if (dstmac != model.address && dstmac != defs.IEEE1905_MULTICAST_MAC)
			return false;

		if (model.isController)
			return this.handle_controller_cmdu(i1905lif, dstmac, srcmac, msg);
		else
			return this.handle_agent_cmdu(i1905lif, dstmac, srcmac, msg);
	}
};

export default proto({
	sessions: []
}, IProtoAutoConf);
