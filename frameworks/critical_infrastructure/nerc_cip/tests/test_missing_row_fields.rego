package nerc_cip.missing_row_fields_test

import rego.v1

# `not f(row.field)` and `not row.field in S` are undefined when the field is missing: the system dropped out of
# the violation list and the check passed.

test_system_without_impact_categorization_is_not_categorized if {
	not data.nerc_cip.cip_002.all_bes_cyber_systems_categorized with input as {"bes_cyber_systems": [{"system_id": "s1"}]}
	data.nerc_cip.cip_002.all_bes_cyber_systems_categorized with input as {"bes_cyber_systems": [{"system_id": "s1", "impact_categorization": "high"}]}
}

test_main_system_without_impact_level_is_reported if {
	v := data.nerc_cip_main.cip_002_violations with input as {"bes_cyber_systems": [{"system_id": "s1"}]}
	"CIP-002: BES Cyber System s1 has no valid impact categorization (high/medium/low)" in v
}

test_system_without_a_recovery_plan_is_not_current if {
	inp := {"bes_cyber_systems": [{"system_id": "s1", "impact_categorization": "high"}], "recovery_plans": {}}
	not data.nerc_cip.cip_009.recovery_plans_current with input as inp
	inp2 := {"bes_cyber_systems": [{"system_id": "s1", "impact_categorization": "high"}]}
	not data.nerc_cip.cip_009.recovery_plans_current with input as inp2
}

test_system_with_a_current_recovery_plan_is_current if {
	inp := {"bes_cyber_systems": [{"system_id": "s1", "impact_categorization": "high"}], "recovery_plans": {"s1": {"last_review_date": "2026-11-01T00:00:00Z"}}}
	data.nerc_cip.cip_009.recovery_plans_current with input as inp with time.now_ns as 1795000000000000000
}
