package cmmc.configuration_management_test

import rego.v1

cfg := {"change_control_process": true, "changes_reviewed_before_implementation": true, "security_impact_analysis": true}

test_no_systems_at_level2_not_compliant if {
	inp := {"cmmc_level": 2, "configuration": cfg, "software": {}}
	not data.cmmc.configuration_management.compliant with input as inp
	v := data.cmmc.configuration_management.violations with input as inp
	some x in v
	startswith(x, "CMMC CM.L2-3.4.1: evidence missing")
}

test_empty_systems_flagged if {
	v := data.cmmc.configuration_management.violations with input as {"cmmc_level": 2, "systems": []}
	some x in v
	startswith(x, "CMMC CM.L2-3.4.1: evidence missing")
}

test_systems_present_not_flagged_as_missing if {
	v := data.cmmc.configuration_management.violations with input as {"cmmc_level": 2, "systems": [{"name": "s1", "baseline_configuration_documented": true, "security_configuration_enforced": true}]}
	every x in v {
		not startswith(x, "CMMC CM.L2-3.4.1: evidence missing")
	}
}

test_failclosed_notice_not_mislabelled_as_3_4_3 if {
	v := data.cmmc.configuration_management.violations with input as {}
	some x in v
	contains(x, "FAIL-CLOSED")
	not contains(x, "3.4.3")
}
