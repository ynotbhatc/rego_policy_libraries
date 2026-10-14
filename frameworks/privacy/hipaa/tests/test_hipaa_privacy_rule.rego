# Tests for hipaa.privacy_rule - 45 CFR Part 164 Subpart E keyed to CFR citations.
package hipaa.privacy_rule_test

import rego.v1

import data.hipaa.privacy_rule as pr
import data.hipaa.test_fixtures as fx

test_counts_pinned if {
	count(pr.requirements) == 110
	count(pr.requirements_table) == 110
	count({id | some id, r in pr.requirements; r.status == "standard"}) == 55
	count({id | some id, r in pr.requirements; r.status == "implementation specification"}) == 55
	count(pr.fact_basis) == 37
	count({id | some id, _ in pr.requirements; not pr.fact_basis[id]}) == 73
	count(pr.sections) == 14
	count({id | some id, r in pr.requirements; not pr.sections[r.section]}) == 0
	count({id | some id, _ in pr.fact_basis; not pr.requirements[id]}) == 0
}

test_every_gate_is_a_known_gate if {
	known := {"", "covered_entity", "provider_or_plan"} | {k | some k, _ in pr.scope_roles}
	count({id | some id, r in pr.requirements; not r.gate in known}) == 0
}

test_empty_input_fails_closed if {
	r := pr.report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED - attestations 'input.hipaa.subpart_e'")

	# 6 undeclared scope flags + no role + missing container + the 13 rows binding any regulated entity
	r.applicable == 13
	r.violation_count == 21
}

test_all_green_is_compliant if {
	r := pr.report with input as fx.full_input
	r.compliant == true
	r.satisfied == 110
	r.violation_count == 0
}

test_one_attestation_false_is_named if {
	inp := object.union(fx.full_input, {"hipaa": {"subpart_e": {"164.530(f)": false}}})
	v := pr.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.530(f) Mitigation (standard): not attested")
}

test_unknown_id_is_a_violation if {
	inp := object.union(fx.full_input, {"hipaa": {"subpart_e": {"164.599(a)": true}}})
	v := pr.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "unknown id 164.599(a)")
}

test_failed_fact_is_named_under_its_citation if {
	inp := object.union(fx.full_input, {"hipaa": {"privacy": {"documentation": {"retention_years": 5}}}})
	v := pr.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.530(j)(2) Retention period (implementation specification): fact check failed")
}

test_de_identification_rows_follow_their_flag if {
	off := object.union(fx.full_input, {"hipaa": {"scope": {"de_identifies_phi": false}, "privacy": {"de_identification": {}}}})
	r := pr.report with input as off
	r.applicable == 107
	r.compliant == true

	on := object.union(fx.full_input, {"hipaa": {"privacy": {"de_identification": {"method": {"documented": false}}}}})
	v := pr.violations with input as on
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.514(b) ")
}

test_business_associate_only_scope if {
	inp := object.union(fx.full_input, {"hipaa": {"scope": object.union(fx.scope_none, {"business_associate": true})}})
	r := pr.report with input as inp
	r.applicable == 13
	r.compliant == true
}
