'use strict';
'require view';
'require rpc';
'require fs';
'require ui';

function loadVisNetworkJS() {
	return new Promise(function (resolveFn, rejectFn) {
		var s = document.querySelector('head').appendChild(E('script', {
			type: 'text/javascript',
			load: resolveFn,
			error: rejectFn
		}));

		s.src = L.resource('umap/vis-network.min.js');
	});
}

var callUmapGetTopology = rpc.declare({
	object: 'umap',
	method: 'get_topology',
	expect: {}
});

var EDGE_LENGTH_MAIN = 200;
var EDGE_LENGTH_SUB = 50;

function edgeLabel(metric) {
	if (metric.rssi != 255)
		return `${metric.rssi}db`;

	if (metric.speed >= 1000) {
		if (metric.speed % 1000)
			return `${(metric.speed / 1000).toFixed(1)}GBit/s`;
		else
			return `${metric.speed / 1000}GBit/s`;
	}
	else {
		return `${metric.speed}MBit/s`;
	}
}

return view.extend({
	load: function () {
		return Promise.all([
			callUmapGetTopology(),
			loadVisNetworkJS()
		]);
	},

	render: function (data) {
		var topo = data[0] || { devices: [], links: [] };
		var container = E('div', { style: 'height:80vh' });
		var edges = [];
		var nodes = [];
		var if2node = {};
		var iedges = {};

		for (var i = 0; i < topo.devices.length; i++) {
			var device = topo.devices[i];

			nodes.push({
				id: device.al_address,
				label: (device.identification?.friendly_name ?? device.al_address),
				image: L.resource('umap/img/Network-Pipe-icon.png'),
				shape: "image",
				opacity: 1.0,
				title: '<strong>Foo</strong><br>\nLala'
			});

			for (let j = 0; j < device.interfaces?.length; j++) {
				let iface = device.interfaces[j];

				if2node[iface.address] = device.al_address;

				for (let remote_address in iface.links) {
					let mac1, mac2;

					if (iface.address < remote_address) {
						mac1 = iface.address;
						mac2 = remote_address;
					}
					else {
						mac1 = remote_address;
						mac2 = iface.address;
					}

					iedges[mac1] ??= {};
					iedges[mac1][mac2] ??= {
						bridge: iface.links[remote_address].is_bridge,
						speed: iface.links[remote_address].speed,
						rssi: iface.links[remote_address].rssi,
						use: 0
					};

					iedges[mac1][mac2].use++;
				}
			}

			for (let k in device.neighbors?.others) {
				for (let l = 0; l < device.neighbors.others[k].length; l++) {
					let mac = device.neighbors.others[k][l];

					nodes.push({
						id: device.neighbors.others[k][l],
						label: device.neighbors.others[k][l],
						image: L.resource('umap/img/Hardware-My-Computer-3-icon.png'),
						shape: "image",
						group: "computer",
						opacity: 1,
					});

					edges.push({
						from: device.al_address,
						to: device.neighbors.others[k][l],
						length: EDGE_LENGTH_SUB,
						title: 'Edge!'
					});
				}
			}
		}

		for (let mac1 in iedges) {
			for (let mac2 in iedges[mac1]) {
				//if (iedges[mac1][mac2].use < 2)
				//	continue;

				if (!if2node[mac1] || !if2node[mac2])
					continue;

				edges.push({
					from: if2node[mac1],
					to: if2node[mac2],
					length: EDGE_LENGTH_MAIN,
					label: edgeLabel(iedges[mac1][mac2]),
					color: iedges[mac1][mac2].bridge ? '#ccc' : null
				});
			}
		}

		new vis.Network(container, {
			nodes: nodes,
			edges: edges
		}, {
			groups: {
				computer: {
					opacity: 0.3
				}
			}
		});

		return E([
			E('h2', {}, _('EasyMesh IEEE.1905 Topology')),
			container
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
