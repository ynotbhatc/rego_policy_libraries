package cis_vyos_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_vyos.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_source_routing_absent_flagged if has("3.1.6", {})

test_source_routing_empty_ip_flagged if has("3.1.6", {"system": {"ip": {}}})

test_source_routing_disabled_ok if not has("3.1.6", {"system": {"ip": {"disable-source-route": null}}})

test_source_routing_disabled_via_firewall_ok if not has("3.1.6", {"firewall": {"ip-src-route": "disable"}})

test_host_validation_not_ssh_v1 if not has("1.1.2", {"service": {"ssh": {"disable-host-validation": null}}})

test_v1_enabled_still_flagged if has("1.1.2", {"service": {"ssh": {"v1-enabled": null}}})

test_control_count_matches_rules if {
	r := data.cis_vyos.compliance_assessment with input as {}
	r.summary.total_controls == 23
}
