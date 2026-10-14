# Tests for hipaa.part162 - 45 CFR Part 162 obligations (transactions, code sets, identifiers).
package hipaa.part162_test

import rego.v1

import data.hipaa.part162 as p
import data.hipaa.test_fixtures as fx

test_counts_pinned if {
	count(p.obligations) == 43
	count({id | some id, r in p.obligations; r.section == "D"}) == 10
	count({id | some id, r in p.obligations; r.section == "I"}) == 15
	count({id | some id, r in p.obligations; r.section == "E"}) == 0 # Subpart E (HPID) is [Reserved]
	count(p.dated_obligations) == 10
	count(p.fact_basis) == 0
}

test_empty_input_fails_closed if {
	r := p.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED - attestations 'input.hipaa.part_162'")

	# 4 scope flags + no role + missing container; every row is gated on an entity type
	r.applicable == 0
	r.violation_count == 6
}

test_all_attested_is_compliant if {
	r := p.compliance_report with input as fx.full_input
	r.compliant == true
	r.satisfied == 43
}

test_provider_only_scope if {
	inp := object.union(fx.full_input, {"hipaa": {"scope": object.union(fx.scope_none, {"health_care_provider": true})}})
	r := p.compliance_report with input as inp
	r.applicable == 32
	r.subparts.D.applicable == 7
	r.compliant == true
}

test_one_attestation_false_is_named if {
	inp := object.union(fx.full_input, {"hipaa": {"part_162": {"162.923(a)": false}}})
	v := p.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 162.923(a) ")
}

test_unknown_id_is_a_violation if {
	inp := object.union(fx.full_input, {"hipaa": {"part_162": {"162.504(a)": true}}})
	v := p.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "unknown id 162.504(a)")
}
