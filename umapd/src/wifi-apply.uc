#!/usr/bin/env ucode

'use strict';

import { cursor } from 'uci';

const ctx = cursor();
const radio = getenv('RADIO');
const network = getenv('NETWORK');
const settings = json(ARGV[0]);

if (type(settings) != 'array' || type(radio) != 'string')
	die("Do not execute this program directly");

const WPS_AUTH_OPEN = 0x0001;
const WPS_AUTH_WPAPSK = 0x0002;
const WPS_AUTH_WPA = 0x0008;
const WPS_AUTH_WPA2 = 0x0010;
const WPS_AUTH_WPA2PSK = 0x0020;
const WPS_AUTH_SAE = 0x0040;

const WPS_ENCR_NONE = 0x0001;
const WPS_ENCR_TKIP = 0x0004;
const WPS_ENCR_AES = 0x0008;

ctx.foreach('wireless', 'wifi-iface', (s) => {
	if (s.device == radio && s.mode == 'ap') {
		ctx.delete('wireless', s['.name']);
	}
});

// Tear down requested, nothing else to do
if (length(settings) == 1 && settings[0]?.multi_ap?.tear_down) {
	ctx.set('wireless', radio, 'disabled', 1);
	ctx.commit('wireless');

	system(['/sbin/wifi', 'up', radio]);
	exit(0);
}

for (let bss in settings) {
	let sid = ctx.add('wireless', 'wifi-iface');
	ctx.set('wireless', sid, 'device', radio);
	ctx.set('wireless', sid, 'mode', 'ap');
	ctx.set('wireless', sid, 'ssid', bss.ssid);
	ctx.set('wireless', sid, 'bssid', bss.bssid);
	ctx.set('wireless', sid, 'network', network ?? 'lan');

	// Determine base encryption type
	let enc;

	if (bss.authentication_types & WPS_AUTH_SAE)
		enc = 'sae';
	else if ((bss.authentication_types & WPS_AUTH_WPA2PSK) && (bss.authentication_types & WPS_AUTH_WPAPSK))
		enc = 'psk2-mixed';
	else if (bss.authentication_types & WPS_AUTH_WPA2PSK)
		enc = 'psk2';
	else if (bss.authentication_types & WPS_AUTH_WPAPSK)
		enc = 'psk';
	else
		enc = 'none';

	// Append cipher types
	let ciphers = [];

	if (bss.encryption_types & WPS_ENCR_TKIP)
		push(ciphers, 'tkip');

	if (bss.encryption_types & WPS_ENCR_AES)
		push(ciphers, 'aes');

	if (length(ciphers))
		enc += '+' + join('+', ciphers);

	ctx.set('wireless', sid, 'encryption', enc);

	if (bss.encryption_types & (WPS_ENCR_TKIP | WPS_ENCR_AES))
		ctx.set('wireless', sid, 'key', bss.network_key);

	// Set multi ap operation mode
	let multi_ap_mode = 0;

	if (bss.multi_ap?.is_backhaul_bss)
		multi_ap_mode |= 1;

	if (bss.multi_ap?.is_fronthaul_bss) {
		multi_ap_mode |= 2;

		for (let other_bss in settings) {
			if (other_bss === bss)
				continue;

			if (!other_bss.multi_ap?.is_backhaul_bss)
				continue;

			if (bss.authentication_types & (WPS_AUTH_WPAPSK | WPS_AUTH_WPA2PSK))
				ctx.set('wireless', sid, 'wps_pushbutton', 1);

			ctx.set('wireless', sid, 'multi_ap_backhaul_ssid', other_bss.ssid);

			if (other_bss.encryption_types & (WPS_ENCR_TKIP | WPS_ENCR_AES))
				ctx.set('wireless', sid, 'multi_ap_backhaul_key', other_bss.network_key);
		}
	}

	ctx.set('wireless', sid, 'multi_ap', multi_ap_mode);
}

ctx.set('wireless', radio, 'disabled', 0);
ctx.commit('wireless');

system(['/sbin/wifi', 'up', radio]);
