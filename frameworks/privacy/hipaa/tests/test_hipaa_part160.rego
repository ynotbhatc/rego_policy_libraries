# Tests for hipaa.part160 - 45 CFR Part 160 obligations of covered entities and business associates.
package hipaa.part160_test

import rego.v1

import data.hipaa.part160 as p
import data.hipaa.test_fixtures as fx

test_counts_pinned if {
	count(p.obligations) == 8
	count({id | some id, r in p.obligations; r.section == "C"}) == 7
	count(p.fact_basis) == 0
	count(p.out_of_scope) == 14
}

test_empty_input_fails_closed if {
	r := p.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED - attestations 'input.hipaa.part_160'")

	# 4 scope flags + no role + missing container + 8 rows
	r.violation_count == 14
}

test_all_attested_is_compliant if {
	r := p.compliance_report with input as fx.full_input
	r.compliant == true
	r.satisfied == 8
}

test_one_attestation_false_is_named if {
	inp := object.union(fx.full_input, {"hipaa": {"part_160": {"160.310(c)(1)": false}}})
	v := p.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 160.310(c)(1) ")
}

test_unknown_id_is_a_violation if {
	inp := object.union(fx.full_input, {"hipaa": {"part_160": {"160.312(a)": true}}})
	v := p.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "unknown id 160.312(a)")
}
