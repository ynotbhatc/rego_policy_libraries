package cmmc.incident_response_test

import rego.v1

full := {"plan_documented": true, "plan_tested": true, "plan_age_days": 30, "incident_tracking_system": true, "reporting_to_dod_required_when_applicable": true, "tabletop_exercise_completed": true}

test_empty_ir_without_level_not_compliant if {
	not data.cmmc.incident_response.compliant with input as {"incident_response": {}}
}

test_missing_level_flagged if {
	v := data.cmmc.incident_response.violations with input as {"incident_response": full}
	some x in v
	contains(x, "FAIL-CLOSED - facts 'input.cmmc_level'")
}

test_full_ir_at_level2_compliant if data.cmmc.incident_response.compliant with input as {"cmmc_level": 2, "incident_response": full}

test_absent_plan_age_flagged if {
	ir := object.remove(full, ["plan_age_days"])
	not data.cmmc.incident_response.compliant with input as {"cmmc_level": 2, "incident_response": ir}
}

test_old_plan_flagged if {
	ir := object.union(full, {"plan_age_days": 500})
	not data.cmmc.incident_response.compliant with input as {"cmmc_level": 2, "incident_response": ir}
}
