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

'use strict';

import * as uloop from 'uloop';

import * as sys from 'umap.core';
import socket from 'umap.socket';
import cmdu from 'umap.cmdu';
import lldp from 'umap.lldp';
import utils from 'umap.utils';
import model from 'umap.model';
import defs from 'umap.defs';
import ubus from 'umap.ubus';
import log from 'umap.log';

import proto_topology from 'umap.proto.topology';
import proto_autoconf from 'umap.proto.autoconf';
import proto_capab from 'umap.proto.capabilities';
import proto_scanning from 'umap.proto.scanning';

const relayed_messages = utils.AgingDict(60000);

function handle_i1905_cmdu(i1905lif, dstmac, srcmac, msg) {
	let al_mac = msg.get_tlv(defs.TLV_IEEE1905_AL_MAC_ADDRESS);

	log.debug('RX %-8s: %s%s > %s%s : %04x (%s) [%d]',
		i1905lif.ifname,
		(srcmac == model.address) ? '*' : '', srcmac,
		(dstmac == model.address) ? '*' : '', dstmac,
		msg.type, utils.cmdu_type_ntoa(msg.type) ?? 'Unknown Type',
		msg.mid);

	for (let i = 0; msg.tlvs[i] != null; i += 3)
		if (msg.tlvs[i] != 0)
			log.debug2('  TLV %02x (%s) - %d byte',
				msg.tlvs[i],
				utils.tlv_type_ntoa(msg.tlvs[i]),
				msg.tlvs[i + 2] - msg.tlvs[i + 1]);

	// ignore packets looped back to us
	if (al_mac == model.address) {
		log.warn(`Ignoring CMDU originating from our AL MAC (network loop?)`);
		return;
	}

	const handled = msg.run_handler()
		|| proto_topology.handle_cmdu(i1905lif, dstmac, srcmac, msg)
		|| proto_autoconf.handle_cmdu(i1905lif, dstmac, srcmac, msg)
		|| proto_capab.handle_cmdu(i1905lif, dstmac, srcmac, msg)
		|| proto_scanning.handle_cmdu(i1905lif, dstmac, srcmac, msg)
		;

	if (!handled)
		log.warn(`Not handling CMDU [${msg.mid}] ${utils.cmdu_type_ntoa(msg.type)}`);

	if (msg.flags & defs.CMDU_F_ISRELAY) {
		const key = `${al_mac}-${msg.mid}`;

		if (relayed_messages.has(key))
			return log.warn(`Already relayed CMDU [${msg.mid}] from ${al_mac} (network loop?)`);

		for (let i1905lif2 in model.getLocalInterfaces())
			if (i1905lif2.ieee1905 && i1905lif2.i1905sock != i1905lif.i1905sock)
				msg.send(i1905lif2.i1905sock, srcmac, defs.IEEE1905_MULTICAST_MAC, defs.CMDU_F_ISRELAY);

		relayed_messages.set(key, true);
	}
}

function handle_i1905_input(flags) {
	let sock = this.handle();

	while (true) {
		let payload = sock.recv();

		if (!payload)
			break;

		let i1905lif = model.lookupLocalInterface(sock);

		if (!i1905lif) {
			log.warn(`Received CMDU on unknown interface (${sock.ifname})`);
			continue;
		}

		let msg = cmdu.parse(payload[1], payload[3]);

		if (!msg)
			log.debug('RX %-8s: %s > %s : Invalid CMDU', sock.ifname, payload[1], payload[0]);
		else if (msg.is_complete())
			handle_i1905_cmdu(i1905lif, payload[0], payload[1], msg);
	}
}

function handle_lldp_input(flags) {
	let sock = this.handle();

	while (true) {
		let payload = sock.recv();

		if (!payload)
			break;

		let msg = lldp.parse(payload[3]);

		if (!msg) {
			log.warn(`Ignoring incomplete/malformed LLDPU`);
			continue;
		}

		if (msg.chassis == model.address) {
			log.warn(`Ignoring LLDPU originating from our AL MAC (network loop?)`);
			continue;
		}

		model.addDevice(msg.chassis).addInterface(msg.port).updateLLDPTimestamp();
	}
}

export default function () {
	uloop.init();

	let opts = sys.getopt([
		'interface|iface|i=s*',
		'bridge|b=s*',
		'radio|phy|r=s*',
		'controller',
		'mac=s',
		'v+',
		'help'
	]);

	if ('help' in opts) {
		print(
			'Usage:\n',
			`       ${ARGV[0]} --help\n`,
			`       ${ARGV[0]} [--role=role] [--mac=02:00:00:00:00:01] [--interface eth0 ...] [--radio phy0 ...]\n`,
			'\n',
			'--interface IFNAME\n',
			'  Use the given network interface as backhaul link\n',
			'\n',
			'--bridge BRIDGE\n',
			'  Automatically pick up backhaul links from ports of the given bridge\n',
			'\n',
			'--radio PHYNAME\n',
			'  Manage the given radio identified by the wiphy name\n',
			'\n',
			'--controller\n',
			'  Act as Multi-AP controller\n',
			'\n',
			'--mac MACADDR\n',
			'  Specify the AL MAC address to use. If omitted, a suitable address is generated\n'
		);
	}

	log.setVerbosity(opts.v);

	if (length(opts.radio)) {
		for (let radio in opts.radio) {
			if (!model.addRadio(radio)) {
				log.error(`Radio phy '${radio}' unusable - aborting.\n`);
				return 1;
			}
		}
	}
	else if (!opts.controller) {
		log.error('Require at least one radio\n');
		return 1;
	}

	if (!length(opts.interface) && !length(opts.bridge)) {
		log.error('Require at least one interface or bridge\n');
		return 1;
	}

	// FIXME: rework this
	model.ubus = ubus;

	for (let ifname in opts.interface) {
		let ifc = model.addLocalInterface(ifname);
		if (ifc?.pending != true) {
			uloop.handle(ifc.i1905sock, handle_i1905_input, uloop.ULOOP_READ | uloop.ULOOP_EDGE_TRIGGER);
			uloop.handle(ifc.lldpsock, handle_lldp_input, uloop.ULOOP_READ | uloop.ULOOP_EDGE_TRIGGER);
		}
		else {
			log.error(`Unable to initialize interface ${ifname}: ${socket.error()}`);
			return 1;
		}
	}

	for (let bridge in opts.bridge) {
		try {
			let br = model.addLocalBridge(bridge);
			for (let ifname, portifc in br?.ports) {
				if (portifc.ieee1905) {
					uloop.handle(portifc.i1905sock, handle_i1905_input, uloop.ULOOP_READ | uloop.ULOOP_EDGE_TRIGGER);
					uloop.handle(portifc.lldpsock, handle_lldp_input, uloop.ULOOP_READ | uloop.ULOOP_EDGE_TRIGGER);
				}
			}
		}
		catch (e) {
			log.error(`Unable to initialize bridge ${bridge}: ${e}`);
			return 1;
		}
	}

	model.isController = !!opts.controller;
	model.initializeAddress();
	model.observeDeviceChanges(function (portifc, added) {
		if (added && portifc.ieee1905) {
			uloop.handle(portifc.i1905sock, handle_i1905_input, uloop.ULOOP_READ | uloop.ULOOP_EDGE_TRIGGER);
			uloop.handle(portifc.lldpsock, handle_lldp_input, uloop.ULOOP_READ | uloop.ULOOP_EDGE_TRIGGER);

			proto_topology.start();
		}
	});

	proto_topology.init();
	proto_autoconf.init();
	proto_capab.init();
	proto_scanning.init();

	if (!ubus.publish())
		log.warn(`Unable to publish umap object: ${ubus.error()}`);

	if (length(model.interfaces) > 0)
		proto_topology.start();

	uloop.run();

	return 0;
};
