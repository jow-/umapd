/*
 * Copyright (c) 2025 Jo-Philipp Wich <jo@mein.io>.
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

import log from 'umap.log';
import model from 'umap.model';
import cmdu from 'umap.cmdu';
import defs from 'umap.defs';
import ubus from 'umap.ubus';
import utils from 'umap.utils';
import wireless from 'umap.wireless';


const REPLY_HANDLER_TIMEOUT = 3000;

const IProtoCapabilities = {
	init: function () {
		ubus.register('query_ap_capability',
			{ macaddress: "00:00:00:00:00:00" },
			this.query_ap_capability);

		ubus.register('query_backhaul_sta_capability',
			{ macaddress: "00:00:00:00:00:00" },
			this.query_backhaul_sta_capability);
	},

	query_ap_capability: function (req) {
		const i1905dev = model.lookupDevice(req.args.macaddress);

		if (!i1905dev)
			return req.reply(null, 4 /* UBUS_STATUS_NOT_FOUND */);;

		const query = cmdu.create(defs.MSG_AP_CAPABILITY_QUERY);

		query.on_reply(response => {
			if (!response)
				return req.reply(null, 7 /* UBUS_STATUS_TIMEOUT */);

			const ret = {
				ap_capability: response.get_tlv(defs.TLV_AP_CAPABILITY),
				radios: {}
			};

			for (let tt in [
				defs.TLV_AP_RADIO_BASIC_CAPABILITIES,
				defs.TLV_AP_HT_CAPABILITIES,
				defs.TLV_AP_VHT_CAPABILITIES,
				defs.TLV_AP_HE_CAPABILITIES,
				defs.TLV_AP_RADIO_ADVANCED_CAPABILITIES,
			]) {
				for (let data in response.get_tlvs(tt)) {
					const mac = data?.radio_unique_identifier;

					if (!mac)
						continue;

					delete data.radio_unique_identifier;

					if (tt == defs.TLV_AP_HE_CAPABILITIES)
						data.supported_he_mcs = hexenc(data.supported_he_mcs);

					ret.radios[mac] ??= {};
					ret.radios[mac][lc(utils.tlv_type_ntoa(tt))] = data;
				}
			}

			return req.reply(ret);
		}, REPLY_HANDLER_TIMEOUT);

		model.sendMulticast(query, i1905dev.al_address);

		return req.defer();
	},

	query_backhaul_sta_capability: function (req) {
		const i1905dev = model.lookupDevice(req.args.macaddress);

		if (!i1905dev)
			return req.reply(null, 4 /* UBUS_STATUS_NOT_FOUND */);

		const query = cmdu.create(defs.MSG_BACKHAUL_STA_CAPABILITY_QUERY);

		query.on_reply(response => {
			if (!response)
				return req.reply(null, 7 /* UBUS_STATUS_TIMEOUT */);

			const ret = {
				radios: {}
			};

			for (let sta_capa in response.get_tlvs(defs.TLV_BACKHAUL_STA_RADIO_CAPABILITIES)) {
				if (sta_capa?.radio_unique_identifier) {
					ret.radios[sta_capa.radio_unique_identifier] = {
						supports_backhaul_sta: true,
						backhaul_sta_connected: sta_capa.mac_address_included,
						backhaul_sta_address: sta_capa.mac_address
					};
				}
			}

			return req.reply(ret);
		}, REPLY_HANDLER_TIMEOUT);

		model.sendMulticast(query, i1905dev.al_address);

		return req.defer();
	},

	handle_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		// disregard CMDUs not directed to our AL
		if (dstmac != model.address)
			return true;

		if (msg.type === defs.MSG_AP_CAPABILITY_QUERY) {
			const reply = cmdu.create(defs.MSG_AP_CAPABILITY_REPORT, msg.mid);

			reply.add_tlv(defs.TLV_AP_CAPABILITY, {
				onchannel_unassoc_sta_metrics: false,
				offchannel_unassoc_sta_metrics: false,
				agent_initiated_rcpi_steering: false
			});

			for (let radio in wireless.radios) {
				reply.add_tlv(defs.TLV_AP_RADIO_BASIC_CAPABILITIES,
					radio.getBasicCapabilities());

				let caps;

				if ((caps = radio.getHTCapabilities()) != null)
					reply.add_tlv(defs.TLV_AP_HT_CAPABILITIES, caps);

				if ((caps = radio.getVHTCapabilities()) != null)
					reply.add_tlv(defs.TLV_AP_VHT_CAPABILITIES, caps);

				if ((caps = radio.getHECapabilities()) != null)
					reply.add_tlv(defs.TLV_AP_HE_CAPABILITIES, caps);

				// TODO: [Profile 2, 3 TLVs]

				reply.add_tlv(defs.TLV_AP_RADIO_ADVANCED_CAPABILITIES, {
					radio_unique_identifier: radio.address,
					combined_front_back: true,
					combined_profile1_profile2: true,
					mscs: false,
					scs: false,
					qos_map: false,
					dscp_policy: false
				});
			}

			log.debug(`capabilities: sending AP capability report to ${srcmac}`);

			reply.send(i1905lif.i1905sock, model.address, srcmac);

			return true;
		}
		else if (msg.type === defs.MSG_AP_CAPABILITY_REPORT) {
			if (!model.isController)
				return true;

			let i1905dev = model.lookupDevice(srcmac);

			if (i1905dev)
				i1905dev.updateTLVs(msg.get_tlvs_raw(
					defs.TLV_AP_RADIO_BASIC_CAPABILITIES,
					defs.TLV_AP_RADIO_ADVANCED_CAPABILITIES,
					defs.TLV_AP_HT_CAPABILITIES,
					defs.TLV_AP_VHT_CAPABILITIES,
					defs.TLV_AP_HE_CAPABILITIES));

			return true;
		}
		else if (msg.type === defs.MSG_BACKHAUL_STA_CAPABILITY_QUERY) {
			const reply = cmdu.create(defs.MSG_BACKHAUL_STA_CAPABILITY_REPORT, msg.mid);

			for (let radio in wireless.radios) {
				reply.add_tlv(defs.TLV_BACKHAUL_STA_RADIO_CAPABILITIES, {
					radio_unique_identifier: radio.address,
					mac_address: radio.getBackhaulStationAddress()
				});
			}

			log.debug(`capabilities: sending backhaul STA capability report to ${srcmac}`);

			reply.send(i1905lif.i1905sock, model.address, srcmac);

			return true;
		}
		else if (msg.type === defs.MSG_BACKHAUL_STA_CAPABILITY_REPORT) {
			if (!model.isController)
				return true;

			let i1905dev = model.lookupDevice(srcmac);

			if (i1905dev) {
				i1905dev.haveStaCapabilities = true;
				i1905dev.updateTLVs(msg.get_tlvs_raw(defs.TLV_BACKHAUL_STA_RADIO_CAPABILITIES));
			}

			return true;
		}

		return false;
	}
};

export default proto({}, IProtoCapabilities);
