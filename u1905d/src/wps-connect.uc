#!/usr/bin/ucode

'use strict';

import * as fs from 'fs';
import * as sys from 'u1905.core';
import * as wlnl from 'nl80211';
import * as socket from 'socket';
import * as libuci from 'uci';
import * as struct from 'struct';

const WPA_SOCKET_PATH = '/var/run/wps';

const WPA_PROTOS = [ 'OSEN', 'RSN', 'WPA', 'WPA2' ];

const WPA_KEY_MGMT_SUITES = [
	'None',
	'DPP',
	'EAP-SHA256', 'EAP-SHA384', 'EAP-SUITE-B-192', 'EAP-SUITE-B', 'EAP',
	'FILS-SHA256', 'FILS-SHA384',
	'FT-FILS-SHA256', 'FT-FILS-SHA384',
	'FT/EAP', 'FT/PSK', 'FT/SAE-EXT-KEY', 'FT/SAE',
	'OSEN',
	'OWE',
	'PSK-SHA256', 'PSK',
	'SAE-EXT-KEY', 'SAE',
];

const WPA_CIPHERS = [
	'AES-128-CMAC',
	'BIP-CMAC-256', 'BIP-GMAC-128', 'BIP-GMAC-256',
	'CCMP', 'CCMP-256',
	'GCMP', 'GCMP-256',
	'NONE',
	'TKIP',
];

function matches(str, offset, choices, ...delims)
{
	for (let choice in choices) {
		let s = substr(str, offset, length(choice));
		let d = chr(ord(str, offset + length(choice)));

		if (s == choice && d in delims)
			return choice;
	}
}

function parse_encryption(flags)
{
	for (let spec in match(flags, /\[[^\]]+\]/g)) {
		let proto, suite, cipher, suites = [], ciphers = [], offset = 1;

		if ((proto = matches(spec[0], offset, WPA_PROTOS, "-")) == null)
			continue;

		offset += length(proto) + 1;

		while ((suite = matches(spec[0], offset, WPA_KEY_MGMT_SUITES, "+", "-")) != null) {
			offset += length(suite) + 1;
			push(suites, suite);
		}

		if (!length(suites))
			continue;

		while ((cipher = matches(spec[0], offset, WPA_CIPHERS, "+", "-", "]")) != null) {
			offset += length(cipher) + 1;
			push(ciphers, cipher);
		}

		if (!length(ciphers))
			continue;

		return { proto, suites, ciphers };
	}
}

function parse_credentials(creds)
{
	let msg = struct.buffer(hexdec(creds));
	let result = { auth: [], encr: [] };
	let t, l;

	while ((t = msg.get('!H')) > 0 && (l = msg.get('!H')) > 0) {
		switch (t) {
		case 0x100e: /* Credentials */
			/* don't read value, continue parsing nested TLVs */
			break;

		case 0x1045: /* SSID */
			if (l > 32) return null;

			result.ssid = msg.get(l);
			break;

		case 0x1003: /* Authentication Type */
			if (l != 2)	return null;

			let auth = msg.get('!H');
			if (auth & 0x0001) push(result.auth, 'open');
			if (auth & 0x0002) push(result.auth, 'psk');
			if (auth & 0x0004) push(result.auth, 'wep');
			if (auth & 0x0008) push(result.auth, 'wpa');
			if (auth & 0x0010) push(result.auth, 'wpa2');
			if (auth & 0x0020) push(result.auth, 'psk2');
			break;

		case 0x100f: /* Encryption Type */
			if (l != 2) return null;

			let encr = msg.get('!H');
			if (encr & 0x0001) push(result.encr, 'none');
			if (encr & 0x0002) push(result.encr, 'wep');
			if (encr & 0x0004) push(result.encr, 'tkip');
			if (encr & 0x0008) push(result.encr, 'aes');
			break;

		case 0x1027: /* Network Key */
			if (l > 64) return null;

			result.key = msg.get(l);
			break;

		case 0x1020: /* BSSID */
			if (l != 6) return null;

			result.bssid = sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ...msg.read('6B'));
			break;

		default:
			msg.pos(msg.pos() + l); /* skip over other attributes */
			break;
		}
	}

	return result;
}

const uci = libuci.cursor();

if (!uci) {
	warn(`Error instantiating uci context: ${libuci.error()}\n`);
	exit(1);
}

let rc = 0, supplicant_pid, supplicant_sock, supplicant_path, reply;

function timems() {
	let t = clock(true);
	return t[0] * 1000 + t[1] / 1000000;
}

function supplicant_waitfor(sock, expect, timeout) {
	timeout ??= 10000;

	let time_start = timems();

	while (timeout > 0) {
		let events = socket.poll(timeout, sock);

		if (length(events) && (events[0][1] & socket.POLLIN)) {
			let response = trim(sock.recv(4096));

			print(`supplicant: <-- ${replace(response, '\n', '\n            <-- ')}\n`);

			let m = match(response, expect);

			if (m != null)
				return m;
		}

		let time_now = timems();

		timeout -= (time_now - time_start);
		time_start = time_now;
	}

	return null;
}

function supplicant_request(sock, cmd, timeout) {
	sock.send(cmd);

	print(`supplicant: --> ${cmd}\n`);

	return supplicant_waitfor(sock, /^[^<].+$/, timeout ?? 5000)?.[0];
}

function determine_phy(radio) {
	let iwinfo = fs.popen(`iwinfo nl80211 phyname '${replace(radio, "'", "'\\''")}'`, 'r');
	if (!iwinfo)
		die(`Error launching iwinfo: ${fs.error()}`);

	return +fs.readfile(`/sys/class/ieee80211/${trim(iwinfo.read('line'))}/index`);
}

function delete_phy_netdevs(phyidx) {
	for (let dev in wlnl.request(wlnl.const.NL80211_CMD_GET_INTERFACE, wlnl.const.NLM_F_DUMP, { wiphy: phyidx })) {
		print(`Deleting interface ${dev.dev}\n`);
		wlnl.request(wlnl.const.NL80211_CMD_DEL_INTERFACE, 0, { dev: dev.dev });
	}
}

function delete_wifi_ifaces(radio) {
	let reload = false;

	uci.load('wireless');

	uci.foreach('wireless', 'wifi-iface', (s) => {
		if (s.device == radio /*&& s.mode == 'sta'*/) {
			uci.delete('wireless', s['.name']);
			reload = true;
		}
	});

	if (reload) {
		uci.save('wireless');
		//system(['wifi', 'reload']);
	}
}

function run_supplicant(ifname) {
	return sys.spawn(['wpa_supplicant', '-q', '-q', '-D', 'nl80211', '-C', WPA_SOCKET_PATH, '-i', ifname]);
}

function perform_wps(args) {
	const ifname = `phy${args.phy}-wps0`;

	try {
		// Deconfigure radio
		system(['/sbin/wifi', 'down', args.radio]);

		// Delete all wifi-iface definitions
		delete_wifi_ifaces(args.radio);

		// Delete all netdevs on phy
		delete_phy_netdevs(args.phy);

		// Spawn temporary netdev for WPS-PBC process
		if (!wlnl.request(wlnl.const.NL80211_CMD_NEW_INTERFACE, 0, { wiphy: args.phy, iftype: wlnl.const.NL80211_IFTYPE_STATION, ifname }))
			die(`Error creating station interface '${ifname}' on phy #${args.phy}: ${wlnl.error()}`);

		supplicant_pid = run_supplicant(ifname);
		supplicant_path = `${WPA_SOCKET_PATH}/${ifname}`;

		// await socket
		for (let attempt = 0; attempt < 50; attempt++) {
			if ((supplicant_sock = socket.connect(supplicant_path, null, { socktype: socket.SOCK_DGRAM })) != null)
				break;

			sleep(100);
		}

		if (!supplicant_sock)
			die(`Error connecting to wpa_supplicant: ${socket.error()}`);

		fs.unlink(`/var/run/wps/client`);
		supplicant_sock.bind('/var/run/wps/client');

		if ((reply = supplicant_request(supplicant_sock, 'ATTACH')) != 'OK' ||
		    (reply = supplicant_request(supplicant_sock, 'SET pmf 1')) != 'OK' ||
		    (reply = supplicant_request(supplicant_sock, 'SET wps_cred_processing 1')) != 'OK')
			die(`Error initializing wpa_supplicant (${reply})`);

		printf("Supplicant initialized\n");

		let wps_cmd = ('multi-ap' in args) ? 'WPS_PBC multi_ap=1' : 'WPS_PBC any';
		if ((reply = supplicant_request(supplicant_sock, wps_cmd)) != 'OK')
			die(`Failure triggering WPS push button sequence (${reply})`);

		let wps_reply = supplicant_waitfor(supplicant_sock, /^<3>WPS-CRED-RECEIVED ([0-9a-fA-F]+)$/, 90000);
		if (wps_reply == null)
			die ("WPS association failed");

		let wps_creds = parse_credentials(wps_reply[1]);
		if (!('ssid' in wps_creds) || !length(wps_creds.auth) || !length(wps_creds.encr))
			die("WPS credentials incomplete");

		let bss_flags = match(supplicant_request(supplicant_sock, 'BSS 0'), /^flags=(.*)$/s)?.[1] ?? '';
		let bss_enc = parse_encryption(bss_flags);
		let ieee80211w = null;
		let encr = null;

		if (bss_enc.proto == 'WPA') {
			encr = 'psk';
		}
		else if (bss_enc.proto == 'RSN' || bss_enc.proto == 'WPA2') {
			if ('PSK-SHA256' in bss_enc.suites) {
				ieee80211w = 2;
				encr = 'psk2';
			}
			else if ('OWE' in bss_enc.suites) {
				ieee80211w = 1;
				encr = ('multi-ap' in args) ? 'psk2' : 'owe';
			}
			else if ('PSK' in bss_enc.suites) {
				encr = 'psk2';
			}
			else if ('SAE' in bss_enc.suites) {
				die('WPA3-SAE does not support WPS onboarding');
			}
			else {
				die(`Unrecognized encryption suite(s) '${join("', '", bss_enc.suites)}'`);
			}
		}
		else {
			die(`Unrecognized encryption protocol '${bss_enc.proto}'`);
		}

		uci.set('network', args.config, 'interface');
		uci.set('network', args.config, 'proto', 'dhcp');

		uci.delete('wireless', args.radio, 'disabled');

		uci.set('wireless', args.config, 'wifi-iface');
		uci.set('wireless', args.config, 'device', args.radio);
		uci.set('wireless', args.config, 'mode', 'sta');
		uci.set('wireless', args.config, 'network', args.config);
		uci.set('wireless', args.config, 'ssid', wps_creds.ssid);
		uci.set('wireless', args.config, 'encryption', encr);
		uci.set('wireless', args.config, 'key', wps_creds.key);
		uci.set('wireless', args.config, 'ieee80211w', ieee80211w);
		uci.set('wireless', args.config, 'multi_ap', ('multi-ap' in args) ? 1 : null);

		uci.commit('network');
		uci.commit('wireless');
	}
	catch (e) {
		warn(`Error: ${e}\n`);
		uci.revert('network');
		uci.revert('wireless');
		rc = 1;
	}

	if (supplicant_sock != null) {
		if ((reply = supplicant_request(supplicant_sock, 'TERMINATE')) == 'OK') {
			sys.waitpid(supplicant_pid);

			supplicant_sock.close();
			supplicant_pid = null;
		}
		else {
			warn(`Graceful shutdown request failed (${reply})\n`);
		}
	}

	if (supplicant_pid !== null)
		sys.kill(supplicant_pid, 'TERM');

	if (args.phy !== null)
		delete_phy_netdevs(args.phy);

	fs.unlink(`/var/run/wps/${ifname}`);
	fs.unlink(`/var/run/wps/client`);
	fs.rmdir('/var/run/wps');

	if (rc == 0) {
		system(['/sbin/wifi', 'up', args.radio]);
		printf("Configuration applied\n");
	}

	exit(rc);
}


const args = sys.getopt([ 'radio=s', 'phy=s', 'config=s', 'multi-ap', 'help' ]);

if ('help' in args) {
	print(
		'Usage:\n',
		`	${ARGV[0]} --help\n`,
		`	${ARGV[0]} [--radio=radioname] [--phy=phyname] [--config=uciname]\n`
	);

	exit(1);
}

if (!('radio' in args)) {
	if ((args.radio = uci.get_first('wireless', 'wifi-device')) == null) {
		warn("No radio argument specified and no radio found in /etc/config/wireless - aborting.\n");
		exit(1);
	}
}

if (uci.get('wireless', args.radio) != 'wifi-device') {
	warn(`Specified radio '${args.radio}' not configured in /etc/config/wireless - aborting.\n`);
	exit(1);
}

if (!('phy' in args)) {
	if ((args.phy = determine_phy(args.radio)) == null) {
		warn(`Unable to resolve wiphy index for radio '${args.radio} - aborting.\n`);
		exit(1);
	}
}
else if (!match(args.phy, /^[0-9]+$/)) {
	let idx = fs.readfile(`/sys/class/ieee80211/${args.phy}/index`);
	if ((args.phy = idx ? +idx : null) == null || args.phy != args.phy) {
		warn(`Specified wiphy '${args.phy}' not found - aborting.\n`);
		exit(1);
	}
}
else if (!filter(fs.glob('/sys/class/ieee80211/*/index'), p => +args.phy == +fs.readfile(p))[0]) {
	warn(`Specified wiphy index #${args.phy} not found - aborting.\n`);
	exit(1);
}

if (!('config' in args)) {
	args.config = 'wwan';
}
else if (!match(args.config, /^[A-Za-z0-9_]+$/)) {
	warn(`Given configuration name '${args.config}' is invalid - aborting.\n`);
	exit(1);
}

print(`Starting WPS-PBC session on radio '${args.radio}' (phy #${args.phy})...\n`);

return perform_wps(args);
