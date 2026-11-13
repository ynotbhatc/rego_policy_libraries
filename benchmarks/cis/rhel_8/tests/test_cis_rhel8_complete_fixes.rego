package cis_rhel8_test

import rego.v1

# Semantic review 2026-11-13: Level 2 profile reaches the roll-up; risk and recommendations derive from string violations.
test_level2_profile_adds_l2_violations if {
	v := data.cis_rhel8.all_violations with input as {"profile": "level2"}
	some x in v
	startswith(x, "CIS L2")
}

test_level2_profile_not_compliant_status if {
	data.cis_rhel8.overall_status != "compliant" with input as {"profile": "level2"}
}

test_level1_profile_has_no_l2_violations if {
	v := data.cis_rhel8.all_violations with input as {"profile": "level1"}
	every x in v {
		not startswith(x, "CIS L2")
	}
}

test_risk_level_not_low_when_violations_exist if {
	s := data.cis_rhel8.executive_summary with input as {}
	s.total_violations > 0
	s.risk_level != "low"
}

test_recommendations_built_from_violation_strings if {
	recs := data.cis_rhel8.generate_recommendations with input as {}
	count(recs) > 0
	some r in recs
	r.control != ""
}
