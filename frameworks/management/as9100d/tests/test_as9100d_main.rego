# Tests for as9100d.main — the roll-up over the seven clause packages.
package as9100d.main_test

import rego.v1

import data.as9100d.main
import data.as9100d_fixture_test as fx

# ── Table integrity across clause modules ───────────────────────────────────

test_seventy_rows_across_seven_clauses if {
	count(main.items) == 70
	count({id | some id, it in main.items; it.kind == "fact"}) == 18
	count({id | some id, it in main.items; it.kind == "attestation"}) == 52
}

test_required_aerospace_additions_are_rows if {
	required := {"8.1.1", "8.1.2", "8.1.3", "8.1.4", "8.4.1", "8.4.2", "8.4.3", "8.5.1.1", "8.5.1.2", "8.5.1.3", "8.5.2", "8.5.3", "8.5.6", "8.6", "8.7.1", "9.1.2", "9.2.1", "9.3.1", "10.2.1", "10.3", "7.1.5.2", "7.2", "7.5.3"}
	count({id | some id in required; not main.items[id]}) == 0
}

test_fact_rows_are_the_documented_evidence_set if {
	facts := {id | some id, it in main.items; it.kind == "fact"}
	facts == {"7.1.5.1", "7.1.5.2", "8.1.2", "8.1.4", "8.4.1", "8.4.2", "8.4.3", "8.5.1.1", "8.5.2", "8.5.6", "8.7.1", "8.7.2", "9.1.2", "9.2.1", "9.2.2", "9.3.1", "10.2.1", "10.2.2"}
}

# ── Fail-closed ─────────────────────────────────────────────────────────────

test_empty_input_is_non_compliant_with_every_row_failing if {
	r := main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	r.clause_modules_loaded == 7
	r.total == 70
	r.passed == 0
	r.failed == 70
	r.attested == 0
	r.fact_evaluated == 0
	r.violation_count == 70
	r.as_of == "evaluation clock"
	main.compliant == false with input as {}
	count(main.violations) == 70 with input as {}
}

test_empty_input_reports_every_clause_family if {
	r := main.compliance_report with input as {}
	{c | some c, _ in r.clauses} == {"4", "5", "6", "7", "8", "9", "10"}
	r.clauses["8"].total == 30
	r.clauses["8"].failed == 30
	r.clauses["8"].package == "as9100d.operation"
	r.clauses["8"].compliant == false
}

test_unknown_clause_id_is_flagged if {
	inp := fx.with_patch("attestations", object.union(fx.full.as9100d.attestations, {"11.1": true}))
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown clause id 11.1")
	main.compliant == false with input as inp
}

test_non_object_attestations_flagged if {
	v := main.violations with input as {"as9100d": {"attestations": ["4.1"]}}
	some msg in v
	contains(msg, "must be an object")
}

test_string_true_is_not_an_attestation if {
	inp := fx.with_patch("attestations/4.1", "true")
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.clauses["4"].gaps == ["4.1"]
}

# ── Full pass ───────────────────────────────────────────────────────────────

test_full_fixture_is_compliant if {
	r := main.compliance_report with input as fx.full
	r.compliant == true
	r.violation_count == 0
	r.passed == 70
	r.failed == 0
	r.attested == 52
	r.fact_evaluated == 18
	r.fact_passed == 18
	r.as_of == "2026-11-11"
	main.compliant with input as fx.full
	count(main.violations) == 0 with input as fx.full
}

test_one_withdrawn_evidence_root_fails_only_its_rows if {
	inp := fx.without_evidence("external_providers")
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 3
	r.fact_evaluated == 15
	r.clauses["8"].gaps == ["8.4.1", "8.4.2", "8.4.3"]
	r.clauses["7"].compliant == true
}

test_report_shape if {
	r := main.compliance_report with input as fx.full
	r.framework == "SAE AS9100D (9100:2016)"
	startswith(r.standard, "SAE AS9100 Rev D")
	r.attestation_items == 52
	r.fact_items == 18
	is_set(r.violations)
	is_object(r.clauses)
	every c in r.clauses {
		is_number(c.total)
		is_array(c.gaps)
		is_boolean(c.compliant)
	}
}
