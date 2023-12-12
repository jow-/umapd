import { pack } from 'struct';
import { open, readfile } from 'fs';

export default {
	type: 0x15,
	name: 'Device identification',

	/** @param string payload */
	decode: (payload) => {
		if (length(payload) != 192)
			return null;

		return {
			friendly_name: trim(substr(payload, 0, 64)),
			manufacturer_name: trim(substr(payload, 64, 64)),
			manufacturer_model: trim(substr(payload, 128, 64))
		};
	},

	/** @param ?string friendly_name
	 *  @param ?string manufacturer_name
	 *  @param ?string manufacturer_model */
	encode: (friendly_name, manufacturer_name, manufacturer_model) => {
		friendly_name ??= trim(readfile('/proc/sys/kernel/hostname'));

		let osrel = open('/etc/os-release', 'r');
		if (osrel) {
			for (let line = osrel.read('line'); length(line); line = osrel.read('line')) {
				let kv = match(line, '^([^=]+)="(.+)"\n?$');

				switch (kv?.[0]) {
				case 'OPENWRT_DEVICE_MANUFACTURER':
					manufacturer_name ??= kv[1];
					break;

				case 'OPENWRT_DEVICE_PRODUCT':
					manufacturer_model ??= kv[1];
					break;
				}
			}

			osrel.close();
		}

		if (manufacturer_model == null || manufacturer_model == 'Generic')
			manufacturer_model = trim(readfile('/tmp/sysinfo/model'));

		return pack('!63sx63sx63sx',
			friendly_name ?? 'Unknown',
			manufacturer_name ?? 'Unknown',
			manufacturer_model ?? 'Unknown'
		);
	},
};
