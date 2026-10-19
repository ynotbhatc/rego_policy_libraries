package nerc_cip.cip_003_test

import rego.v1

import data.nerc_cip.cip_003 as c

# Validation 2026-10-17: an absent BES Cyber System inventory does not waive R3.

test_no_inventory_does_not_waive_low_impact_plan if {
	not c.low_impact_plan_implemented with input as {}
	not c.low_impact_plan_reviewed with input as {}
}

test_inventory_without_low_systems_waives_r3 if {
	i := {"bes_cyber_systems": [{"system_id": "S1", "impact_categorization": "high"}]}
	c.low_impact_plan_implemented with input as i
	c.low_impact_plan_reviewed with input as i
}

test_low_system_requires_plan if {
	i := {"bes_cyber_systems": [{"system_id": "S1", "impact_categorization": "low"}]}
	not c.low_impact_plan_implemented with input as i
}

test_low_system_with_plan_passes if {
	i := {
		"bes_cyber_systems": [{"system_id": "S1", "impact_categorization": "low"}],
		"low_impact_plan": {
			"documented": true,
			"approved": true,
			"physical_security_controls": true,
			"electronic_access_controls": true,
			"cyber_security_incident_response": true,
			"transient_cyber_asset_controls": true,
		},
	}
	c.low_impact_plan_implemented with input as i
}

# decisions 2026-10-19: every requirement that gates compliant also yields a violation.
test_failing_r3_r4_produce_violations if {
	vs := c.violations with input as {}
	reqs := {v.requirement | some v in vs}
	"R3" in reqs
	"R4" in reqs
	count([v | some v in vs; v.requirement == "R4"]) == 3
	count([v | some v in vs; v.requirement == "R3"]) == 2
}

test_r4_removable_media_violation_alone if {
	i := {"transient_cyber_assets": {
		"policy_documented": true,
		"asset_management": {"inventory_maintained": true, "authorization_required": true},
		"controls": {"malicious_code_prevention": true, "security_patches": {"applied": true, "documented": true}},
	}}
	vs := c.violations with input as i
	count([v | some v in vs; v.requirement == "R4"]) == 1
}
