package cra.oss_steward_test

import rego.v1

# Validation fixes 2026-10-17: undeclared threshold facts and scope-of-duty facts are violations.

m := data.cra.oss_steward

threshold_true := {
	"is_legal_person": true, "not_manufacturer_of_product": true, "provides_systematic_sustained_support": true,
	"ensures_product_viability": true, "oss_product_intended_for_commercial_activities": true,
}

steward_ok := {"oss_steward": object.union(threshold_true, {
	"involved_in_development": false, "provides_development_infrastructure": false,
	"cybersecurity_policy": {"documented_verifiably": true, "covers_vulnerability_handling": true, "covers_secure_development_practices": true, "fosters_voluntary_reporting_and_sharing": true},
	"cvd_policy": {"in_place": true},
	"vulnerability_reporting_channel": {"exists": true},
	"cooperation": {"with_market_surveillance": true, "policy_providable_on_reasoned_request": true},
	"csirt_coordinator_identified": true,
	"can_ensure_corrective_action": true,
})}

test_steward_empty_input_not_compliant if {
	not m.compliant with input as {}
}

test_steward_each_undeclared_threshold_fact_is_violation if {
	every f in ["is_legal_person", "not_manufacturer_of_product", "provides_systematic_sustained_support", "ensures_product_viability", "oss_product_intended_for_commercial_activities"] {
		not m.compliant with input as {"oss_steward": json.remove(threshold_true, [concat("", ["/", f])])}
	}
}

test_steward_declared_below_threshold_is_not_applicable if {
	m.compliant with input as {"oss_steward": object.union(threshold_true, {"provides_systematic_sustained_support": false})}
}

test_steward_fully_compliant if {
	m.compliant with input as steward_ok
}

test_steward_undeclared_scope_of_duty_is_violation if {
	every f in ["involved_in_development", "provides_development_infrastructure"] {
		not m.compliant with input as json.remove(steward_ok, [concat("", ["/oss_steward/", f])])
	}
}

test_steward_involved_unnotified_exploited_vuln_is_violation if {
	i := json.patch(steward_ok, [
		{"op": "replace", "path": "/oss_steward/involved_in_development", "value": true},
		{"op": "add", "path": "/oss_steward/actively_exploited_vuln_known", "value": true},
	])
	not m.compliant with input as i
}
