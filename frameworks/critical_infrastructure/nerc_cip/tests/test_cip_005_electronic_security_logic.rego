package nerc_cip.cip_005_test

import rego.v1

import data.nerc_cip.cip_005 as c

# Validation 2026-10-17.

systems := [
	{"system_id": "S1", "impact_categorization": "high"},
	{"system_id": "S2", "impact_categorization": "low"},
]

test_low_impact_system_does_not_fail_unused_ports if {
	i := {"bes_cyber_systems": systems, "network_port_management": {"S1": {"unused_ports_disabled": true}}}
	c.unused_ports_disabled with input as i
}

test_high_impact_system_with_ports_open_fails if {
	i := {"bes_cyber_systems": systems, "network_port_management": {"S1": {"unused_ports_disabled": false}}}
	not c.unused_ports_disabled with input as i
}

test_high_impact_system_without_port_record_fails if {
	i := {"bes_cyber_systems": systems, "network_port_management": {}}
	not c.unused_ports_disabled with input as i
	not c.unused_ports_disabled with input as {}
}

test_missing_remote_sessions_not_encrypted_or_monitored if {
	not c.remote_access_encrypted with input as {}
	not c.remote_access_monitored with input as {}
	c.remote_access_encrypted with input as {"remote_access_sessions": []}
	c.remote_access_monitored with input as {"remote_access_sessions": [{"encryption_enabled": true, "session_monitoring": true}]}
	not c.remote_access_encrypted with input as {"remote_access_sessions": [{"encryption_enabled": false}]}
}

test_no_eaps_not_controlled if {
	not c.electronic_access_points_controlled with input as {}
	not c.electronic_access_points_controlled with input as {"electronic_access_points": []}
}
