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
import wireless from 'umap.wireless';
import ubus from 'umap.ubus';

import { readfile } from 'fs';
import { timer } from 'uloop';
import { request as wlrequest, listener as wllistener, 'const' as wlconst, error as wlerror } from 'nl80211';


wlconst.NL80211_CMD_ABORT_SCAN ??= wlconst.NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH + 2;

const SCAN_FLAG_AP_SCAN = (1 << 2);

const scanTasks = [];
const scanReports = {};

function encodeNoise(dbm) {
	let enc = (dbm + 202) / 2;

	if (enc >= 221 && enc <= 224)
		enc = 225;

	return max(min(enc, 255), 0);
}

function encodeSignal(mbm) {
	if (mbm == null)
		return 255;

	if (mbm < -10950)
		return 0;

	if (mbm < 0)
		return 2 * (mbm + 11000) / 100;

	return 220;
}

function decodeNoise(enc) {
	if (enc == 225)
		return 242;

	return enc * 2 - 202;
}

function decodeSignal(dbm) {
	if (dbm === 255)
		return null;

	if (dbm === 0)
		return -109.5;

	if (dbm < 220)
		return (100 * dbm / 2 - 11000) / 100.0;

	return 0;
}

function getTimestamp() {
	const now = clock();
	const tm = gmtime(now[0]);

	return sprintf('%04d-%02d-%02dT%02d:%02d:%02d.%03dZ',
		tm.year, tm.mon, tm.mday,
		tm.hour, tm.min, tm.sec,
		now[1] / 1000000);
}

function fetchNetlinkScanResults(ifname, frequency_tlvs) {
	const scandata = wlrequest(wlconst.NL80211_CMD_GET_SCAN, wlconst.NLM_F_DUMP, { dev: ifname });
	const surveydata = wlrequest(wlconst.NL80211_CMD_GET_SURVEY, wlconst.NLM_F_DUMP, { dev: ifname });

	for (let entry in surveydata) {
		const survey = entry.survey_info;

		for (let tlv in frequency_tlvs[survey?.frequency]) {
			tlv.utilization = survey.time ? (survey.busy * 255) / survey.time : 0;
			tlv.noise = encodeNoise(survey.noise);
		}
	}

	for (let entry in scandata) {
		let ssid, load, sta_count;
		let ht_width = "20";
		let vht_width;
		let bss_color = 0;

		for (let ie in entry.bss?.information_elements) {
			switch (ie?.type) {
				// SSID
				case 0:
					ssid = ie.data;
					break;

				// BSS load
				case 11:
					sta_count = (ord(ie.data, 1) << 8) | ord(ie.data, 0);
					load = ord(ie.data, 2);
					break;

				// Supported operating classes
				case 59:
					opc = ord(ie.data, 0);
					break;

				// HT operation
				case 61:
					if ((ord(ie.data, 1) & 0x03) in [1, 3])
						ht_width = "40";
					break;

				// VHT operation
				case 192:
					switch (ord(ie.data, 0)) {
						case 0:
							vht_width = "40";
							break;

						case 1:
							vht_width = "80";
							break;

						case 2:
							vht_width = "160";
							break;

						case 3:
							vht_width = "80+80";
							break;
					}
					break;

				// Extension
				case 255:
					switch (ord(ie.data, 0)) {
						// HE operation
						case 36:
							bss_color = ord(ie.data, 4) & 0x3f;
							break;
					}
			}
		}

		for (let tlv in frequency_tlvs[entry.bss.frequency]) {
			if (tlv.scan_status == 0x04)
				tlv.scan_status = 0x00;

			push(tlv.neighbors ??= [], {
				bssid: entry.bss.bssid,
				ssid: ssid,
				signal_strength: encodeSignal(entry.bss.signal_mbm),
				channel_bandwidth: vht_width ?? ht_width ?? "20",
				bss_load_element_present: load != null,
				bss_color: bss_color,
				channel_utilization: load,
				station_count: sta_count,
			});
		}
	}
}

const IActiveScanTask = {
	new: function (i1905lif, srcmac, req) {
		const scanTask = {
			i1905lif: i1905lif,
			srcmac: srcmac,
			pending: {},
			tlvs: {}
		};

		const ts = getTimestamp();

		for (let requested_radio in req.radios) {
			const radio = wireless.lookupRadioByAddress(requested_radio.radio_unique_identifier);

			if (!radio) {
				log.warn(`scanning: ignoring scan request for unknown radio ${requested_radio.radio_unique_identifier}`);
				continue;
			}

			let supported_opclasses = radio.getSupportedOperatingClasses();
			let frequency_tlvs = {};
			let result_tlvs = (scanTask.tlvs[radio.address] ??= {});

			for (let requested_opclass in requested_radio.opclasses) {
				let opclass = wireless.lookupOperatingClass(requested_opclass.opclass);

				if (!opclass) {
					log.warn(`scanning: invalid operating class ${requested_opclass.opclass} requested`);

					(result_tlvs[requested_opclass.opclass] ??= {})[0] = {
						scan_status: 0x01, /* Scan not supported on opclass/channel */
					};

					continue;
				}

				const supported_opclass = filter(supported_opclasses, e => e.opclass == opclass.opc)[0];

				if (!supported_opclass) {
					log.warn(`scanning: unsupported operating class ${opclass.opc} requested`);

					/* If no specific channels where requested, respond with one global report TLV,
					   otherwise signal each requested channel individually */
					for (let ch in length(requested_opclass.channels) ? requested_opclass.channels : [0]) {
						(result_tlvs[opclass.opc] ??= {})[ch] = {
							scan_status: 0x01, /* Scan not supported on opclass/channel */
						};
					}

					continue;
				}

				const channels = [];

				if (length(requested_opclass.channels)) {
					for (let ch in requested_opclass.channels) {
						if (!(ch in opclass.channels)) {
							log.warn(`scanning: invalid channel ${ch} requested`);

							(result_tlvs[opclass.opc] ??= {})[ch] = {
								scan_status: 0x01, /* Scan not supported on opclass/channel */
							};

							continue;
						}

						push(channels, ch);
					}
				}
				else {
					push(channels, ...opclass.channels);
				}

				for (let ch in channels) {
					if (ch in supported_opclass.statically_non_operable_channels)
						continue;

					const freq = wireless.channelToFrequency(opclass.band, ch);

					if (!freq)
						continue;

					push(frequency_tlvs[freq] ??= [],
						(result_tlvs[opclass.opc] ??= {})[ch] = {
							scan_status: 0x04, /* Pending... */
							timestamp: ts,
						}
					);
				}
			}

			let wdevs = wlrequest(wlconst.NL80211_CMD_GET_INTERFACE, wlconst.NLM_F_DUMP, {
				wiphy: radio.info?.wiphy
			});

			if (!length(wdevs))
				return log.warn(`scanning: no wdev on radio ${radio.address} - unable to scan`);

			/* abort other scans on the same phy */
			for (let otherScanTask in scanTasks) {
				for (let otherIfname in otherScanTask.pending) {
					const otherWiphy = +readfile(`/sys/class/net/${otherIfname}/phy80211/index`);

					if (otherWiphy == radio.info.wiphy) {
						wlrequest(wlconst.NL80211_CMD_ABORT_SCAN, 0, { dev: otherIfname });
						otherScanTask.update(otherIfname, true);
					}
				}
			}

			const ifname = sort(wdevs, (a, b) => b.iftype - a.iftype)[0].ifname;

			log.info(`scanning: initiating scan on radio ${radio.address}, wdev ${ifname}`);

			scanTask.pending[ifname] = frequency_tlvs;
			scanTask.timeout = timer(60000, function () {
				for (let ifname in scanTask.pending) {
					wlrequest(wlconst.NL80211_CMD_ABORT_SCAN, 0, { dev: ifname });
					scanTask.update(ifname, true);
				}
			});

			wlrequest(wlconst.NL80211_CMD_TRIGGER_SCAN, 0, {
				dev: ifname,
				scan_flags: SCAN_FLAG_AP_SCAN,
				scan_frequencies: sort(map(keys(frequency_tlvs), f => +f)),
			});
		}

		return push(scanTasks, proto(scanTask, this));
	},

	update: function (ifname, aborted) {
		const frequency_tlvs = this.pending[ifname];

		if (!frequency_tlvs)
			return;

		log.info(`scanning: ${aborted ? 'aborted' : 'completed'} scan on wdev ${ifname}`);

		fetchNetlinkScanResults(ifname, frequency_tlvs);

		delete this.pending[ifname];

		if (!length(this.pending))
			this.reply(aborted);
	},

	reply: function (aborted) {
		/* finalize TLVs */
		const msg = cmdu.create(defs.MSG_CHANNEL_SCAN_REPORT);

		msg.add_tlv(defs.TLV_TIMESTAMP, getTimestamp());

		for (let radio_unique_identifier, opclasses in this.tlvs) {
			const report = [];

			for (let opclass, channels in opclasses) {
				for (let channel, data in channels) {
					push(report, {
						...data,
						radio_unique_identifier,
						opclass: +opclass,
						channel: +channel,
						scan_status: (data.scan_status == 0x04)
							? (aborted ? 0x05 : 0x00)
							: data.scan_status,
						aggregate_scan_duration: 100, // NB: we do not have a way to measure this with nl80211
						active_scan: true,
						neighbors: data.neighbors ?? [],
					});
				}
			}

			for (let tlv in report)
				msg.add_tlv(defs.TLV_CHANNEL_SCAN_RESULT, tlv);

			// cache results for later use
			scanReports[radio_unique_identifier] = report;
		}

		msg.send(this.i1905lif.i1905sock, model.address, this.srcmac);

		this.timeout.cancel();

		for (let i = 0; i < length(scanTasks); i++) {
			if (scanTasks[i] === this) {
				splice(scanTasks, i, 1);
				break;
			}
		}
	}
};

function lookupDeviceByRadio(ruid) {
	for (let i1905dev in model.getDevices()) {
		const ap_capa = i1905dev.getBasicAPCapability(ruid);

		if (ap_capa)
			return [i1905dev, ap_capa];
	}
}

const IProtoScanning = {
	init: function () {
		wllistener(function (ev) {
			const aborted = (ev.cmd == defs.NL80211_CMD_SCAN_ABORTED);

			for (let scanTask in scanTasks)
				scanTask.update(ev.msg.dev, aborted);
		}, [
			wlconst.NL80211_CMD_NEW_SCAN_RESULTS,
			wlconst.NL80211_CMD_SCAN_ABORTED
		]);

		ubus.register('initiate_scan', {
			macaddress: "00:00:00:00:00:00",
			radios: {},
			cached: false
		}, this.initiate_scan);
	},

	initiate_scan: function (req) {
		let i1905dev;
		let ap_capas = {};

		/* device address given, lookup */
		if (req.args.macaddress) {
			i1905dev = model.lookupDevice(req.args.macaddress);

			if (!i1905dev)
				return req.reply(null, 4 /* UBUS_STATUS_NOT_FOUND */); /* device not found */

			for (let ruid in req.args.radios)
				if ((ap_capas[ruid] = dev.getBasicAPCapability(ruid)) == null)
					return req.reply(null, 4 /* UBUS_STATUS_NOT_FOUND */); /* radio on device not found */
		}

		/* device address omitted, lookup by radios */
		else {
			for (let ruid in req.args.radios) {
				let rv = lookupDeviceByRadio(ruid);

				if (!rv)
					return req.reply(null, 4 /* UBUS_STATUS_NOT_FOUND */); /* no device with specified ruid found */

				i1905dev ??= rv[0];

				if (rv[0] !== i1905dev)
					return req.reply(null, 2 /* UBUS_STATUS_INVALID_ARGUMENT */); /* radios refer to different devices */

				ap_capas[ruid] = rv[1];
			}

			if (!i1905dev)
				return req.reply(null, 2 /* UBUS_STATUS_INVALID_ARGUMENT */); /* neither address nor radio given */
		}

		/* no radios specified, determine all */
		if (!length(ap_capas)) {
			for (let ap_capa in i1905dev.getBasicAPCapability(null))
				ap_capas[ap_capa.radio_unique_identifier] = ap_capa;

			if (!length(ap_capas))
				return req.reply(null, 5 /* UBUS_STATUS_NO_DATA */); /* device has no radios */
		}

		const scan_params = {
			perform_fresh_scan: !req.args.cached,
			radios: []
		};

		for (let ruid, ap_capa in ap_capas) {
			let request_opclasses;

			if (req.args.cached)
				request_opclasses = [];
			else if (length(req.args.radios?.[ruid]))
				request_opclasses = map(req.args.radios[ruid], opc => {
					return (type(opc) == 'object')
						? { opclass: +opc.opclass, channels: opc.channels }
						: { opclass: +opc, channels: [] };
				});
			else
				request_opclasses = map(ap_capa.opclasses_supported, opc => ({
					opclass: opc.opclass,
					channels: []
				}));

			push(scan_params.radios, {
				radio_unique_identifier: ruid,
				opclasses: request_opclasses,
			});
		}

		const msg = cmdu.create(defs.MSG_CHANNEL_SCAN_REQUEST);

		msg.add_tlv(defs.TLV_CHANNEL_SCAN_REQUEST, scan_params);
		msg.on_reply(response => {
			if (!response)
				return req.reply(null, 7 /* UBUS_STATUS_TIMEOUT */);

			return req.reply(scan_params);
		}, 60100, defs.MSG_IEEE1905_ACK);

		for (let i1905lif in model.getLocalInterfaces())
			msg.send(i1905lif.i1905sock, model.address, i1905dev.al_address);

		return req.defer();
	},

	handle_cmdu: function (i1905lif, dstmac, srcmac, msg) {
		// disregard CMDUs not directed to our AL
		if (dstmac != model.address)
			return true;

		if (msg.type === defs.MSG_CHANNEL_SCAN_REQUEST) {
			const req = msg.get_tlv(defs.TLV_CHANNEL_SCAN_REQUEST);

			if (!req) {
				log.warn(`scanning: ignoring request message without scan request TLV`);
				return true;
			}

			if (!length(req.radios)) {
				log.warn(`scanning: ignoring request message without radios in request TLV`);
				return true;
			}

			const ack = cmdu.create(defs.MSG_IEEE1905_ACK, msg.mid);
			ack.send(i1905lif.i1905sock, model.address, srcmac);

			// requested cached results
			if (!req.perform_fresh_scan) {
				const msg = cmdu.create(defs.MSG_CHANNEL_SCAN_REPORT);

				msg.add_tlv(defs.TLV_TIMESTAMP, getTimestamp());

				for (let requested_radio in req.radios) {
					if (scanReports[requested_radio.radio_unique_identifier]) {
						for (let tlv in scanReports[requested_radio.radio_unique_identifier])
							msg.add_tlv(defs.TLV_CHANNEL_SCAN_RESULT, tlv);
					}
					else {
						msg.add_tlv(defs.TLV_CHANNEL_SCAN_RESULT, {
							radio_unique_identifier: requested_radio.radio_unique_identifier,
							opclass: 0,
							channel: 0,
							scan_status: 0x04, /* Not completed */
						});
					}
				}

				msg.send(i1905lif.i1905sock, model.address, srcmac);
			}
			else {
				IActiveScanTask.new(i1905lif, srcmac, req);
			}

			return true;
		}
		else if (msg.type === defs.MSG_CHANNEL_SCAN_REPORT) {
			const ret = {
				timestamp: msg.get_tlv(defs.TLV_TIMESTAMP),
				radios: {}
			};

			for (let result_tlv in msg.get_tlvs(defs.TLV_CHANNEL_SCAN_RESULT)) {
				push(ret.radios[result_tlv.radio_unique_identifier] ??= [], {
					opclass: result_tlv.opclass,
					channel: result_tlv.channel,
					scan_status: result_tlv.scan_status_name,
					timestamp: result_tlv.timestamp,
					utilization: result_tlv.utilization,
					noise: decodeNoise(result_tlv.noise),
					aggregate_scan_duration: result_tlv.aggregate_scan_duration,
					active_scan: result_tlv.active_scan,
					bsses: map(result_tlv.neighbors, n => ({
						...n,
						signal_strength: decodeSignal(n.signal_strength)
					}))
				});
			}

			ubus.notify('channel_scan_report', ret);

			return true;
		}

		return false;
	}
};

export default proto({}, IProtoScanning);
