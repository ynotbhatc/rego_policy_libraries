package nerc_cip.cip_007_test

import rego.v1

import data.nerc_cip.cip_007 as c

# Validation 2026-10-17: impact filter and missing-evidence handling.

systems := [
	{"system_id": "H1", "impact_categorization": "high"},
	{"system_id": "L1", "impact_categorization": "low"},
]

good := {
	"bes_cyber_systems": systems,
	"network_port_management": {"H1": {"physical_ports": {"unused_disabled": true}}},
	"system_configurations": {"H1": {"default_passwords": {"changed": true}}},
	"system_access_controls": {"H1": {"account_lockout_configured": true}},
}

test_low_impact_system_does_not_fail_requirements if {
	c.physical_io_ports_protected with input as good
	c.default_passwords_changed with input as good
	c.login_attempt_limiting with input as good
}

test_high_impact_failures_detected if {
	i1 := json.patch(good, [{"op": "replace", "path": "/network_port_management/H1/physical_ports/unused_disabled", "value": false}])
	not c.physical_io_ports_protected with input as i1
	i2 := json.patch(good, [{"op": "replace", "path": "/system_configurations/H1/default_passwords/changed", "value": false}])
	not c.default_passwords_changed with input as i2
	i3 := json.patch(good, [{"op": "replace", "path": "/system_access_controls/H1/account_lockout_configured", "value": false}])
	not c.login_attempt_limiting with input as i3
}

test_missing_records_fail_closed if {
	i := {"bes_cyber_systems": systems}
	not c.physical_io_ports_protected with input as i
	not c.default_passwords_changed with input as i
	not c.login_attempt_limiting with input as i
	not c.physical_io_ports_protected with input as {}
}

test_missing_inventory_fails_per_system_requirements if {
	not c.ports_and_services_minimized with input as {}
	not c.security_patches_applied with input as {}
	not c.malicious_code_prevention_implemented with input as {}
	not c.security_event_logging_enabled with input as {}
	not c.unique_authentication_credentials with input as {}
}

test_patch_evaluation_accepts_iso_dates if {
	p := {"applicable": true, "availability_date": "2026-01-01T00:00:00Z", "evaluation": {"completed": true, "completion_date": "2026-01-20T00:00:00Z"}}
	c.security_patch_evaluation_timely with input as {"security_patches": [p]}
	late := json.patch(p, [{"op": "replace", "path": "/evaluation/completion_date", "value": "2026-03-20T00:00:00Z"}])
	not c.security_patch_evaluation_timely with input as {"security_patches": [late]}
}
