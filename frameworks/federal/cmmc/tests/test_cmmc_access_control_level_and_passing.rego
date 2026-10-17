package cmmc.access_control_test

import rego.v1

l2_clean := {
	"cmmc_level": 2,
	"users": [],
	"access_controls": {},
	"session": {},
}

test_missing_cmmc_level_fails_closed if {
	inp := {"users": [], "access_controls": {"least_privilege_enforced": true, "external_connections_controlled": true}}
	not data.cmmc.access_control.compliant with input as inp
	v := data.cmmc.access_control.violations with input as inp
	some x in v
	contains(x, "FAIL-CLOSED - facts 'input.cmmc_level'")
}

test_level_present_has_no_fail_closed_violation if {
	v := data.cmmc.access_control.violations with input as l2_clean
	every x in v {
		not contains(x, "FAIL-CLOSED")
	}
}

test_passing_counts_practices_not_violations if {
	inp := {"cmmc_level": 1, "users": [
		{"username": "a", "authorized": false, "system_access": true},
		{"username": "b", "authorized": false, "system_access": true},
	]}
	r := data.cmmc.access_control.compliance_report with input as inp
	r.violation_count == 4
	r.passing == 19
}
