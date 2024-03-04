import { pack } from 'struct';
import utils from 'u1905.utils';
import defs from 'u1905.defs';

/**
 * @typedef {Object} U1905TLVMetricReportingPolicy
 * @property {number} local_steering_disallowed_sta
 * STA MAC addresses for which local steering is disallowed.
 * @property {string[]} btm_steering_disallowed_sta
 * TA MAC addresses for which BTM steering is disallowed.
 * @property {U1905TLVSteeringPolicyRule[]}
 * Array of policy objects
 */

/**
 * @typedef {Object} U1905TLVSteeringPolicyRule
 * @property {string} radio_unique_id
 * Radio unique identifier of an AP radio for which Multi-AP control policies
 * are being provided.
 * @property {number} steering_policy
 * Steering policy ID.
 * @property {number} steering_policy_name
 * Steering policy name
 * STA MAC addresses for which BTM steering is disallowed.
 * @property {number} channel_utilization_threshold
 * Channel Utilization Threshold.
 * @property {number} rcpi_steering_threshold
 * RCPI Steering Threshold.
 */

export default {
	type: 0x8a,
	name: 'Metric Reporting Policy',

	/** @param string payload */
	decode: (payload) => {
		let len = length(payload);

		if (len < 2)
			return null;

        const ap_metrics_reporting_interval = ord(payload, 0);
        const number_of_radios = ord(payload, 1);

        for (let i = 0, offset = 2; i < number_of_radios; i++, offset += 10) {
            if (offset + 10 >= len)
                return null;

            const radio_unique_id = utils.ether_ntoa(payload, offset);
            const sta_metrics_reporting_rcpi_threshold = ord(payload, offset + 6);
            const sta_metrics_reporting_rcpi_hysteresis_margin_override = ord(payload, offset + 7);
            const ap_metrics_channel_utilization_reporting_threshold = ord(payload, offset + 8);
            const sta_metrics_inclusion_policy = ord(payload, offset + 9);

            push(rv.radios ??= [], {
                radio_unique_id,
                sta_metrics_reporting_rcpi_threshold,
                sta_metrics_reporting_rcpi_hysteresis_margin_override,
                ap_metrics_channel_utilization_reporting_threshold,
                associated_sta_traffic_stats_included: !!(sta_metrics_inclusion_policy & 0b10000000),
                associated_sta_link_metrics_included: !!(sta_metrics_inclusion_policy & 0b01000000)
            });
        }

        const radio_unique_id = utils.ether_ntoa(payload, 2);
        const sta_metrics_reporting_rcpi_threshold = ord(payload, 8);
        const sta_metrics_reporting_rcpi_hysteresis_margin_override = ord(payload, 9);

        if (rcpi_threshold > 220)
            return null;

        return {
            ap_metrics_reporting_interval,
            number_of_radios,
            radio_unique_id,
            sta_metrics_reporting_rcpi_threshold,
            sta_metrics_reporting_rcpi_hysteresis_margin_override
        };
	},

	/** @param {U1905TLVSteeringPolicy[]} policy */
	encode: (policy) => {
		let fmt = ['!'];
		let val = [];

		const local_disallowed_count = length(policy.local_steering_disallowed_sta);
		const btm_disallowed_count = length(policy.btm_steering_disallowed_sta);

		if (local_disallowed_count > 255 || btm_disallowed_count > 255)
			return null;

		push(fmt, 'B');
		push(val, local_disallowed_count);

		for (let mac in policy.local_steering_disallowed_sta) {
			push(fmt, '6s');
			push(val, utils.ether_aton(mac));
		}

		push(fmt, 'B');
		push(val, btm_disallowed_count);

		for (let mac in policy.btm_steering_disallowed_sta) {
			push(fmt, '6s');
			push(val, utils.ether_aton(mac));
		}

		const policy_count = length(policy.policies);

		if (policy_count > 255)
			return null;

		push(fmt, 'B');
		push(val, policy_count);

		for (let rule in policy.policies) {
			push(fmt, '6s');
			push(val, utils.ether_aton(rule.radio_unique_id));

			if (!defs.STEERING_POLICY[rule.steering_policy])
				return null;

			push(fmt, 'B');
			push(val, rule.steering_policy);

			if (rule.channel_utilization_threshold < 0 || rule.channel_utilization_threshold > 100)
				return null;

			push(fmt, 'B');
			push(val, rule.channel_utilization_threshold * 255 / 100);

			push(fmt, 'B');
			push(val, min(max(rule.rcpi_steering_threshold, -110), 0) * 2 + 220);
		}

		return pack(join('', fmt), ...val);
	},
};
