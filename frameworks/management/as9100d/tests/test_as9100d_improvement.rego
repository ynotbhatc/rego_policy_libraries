# Tests for as9100d.improvement — SAE AS9100D clause 10 (Improvement): one pass and one fail case per row,
# evidence-missing and failing-evidence cases for every fact-decided row, generated from the clause table.
package as9100d.improvement_test

import rego.v1

import data.as9100d.improvement as mod
import data.as9100d_fixture_test as fx

# ── Table integrity ─────────────────────────────────────────────────────────

test_table_has_4_rows if {
	count(mod.items) == 4
	count({id | some id, it in mod.items; it.kind == "attestation"}) == 2
	count({id | some id, it in mod.items; it.kind == "fact"}) == 2
}

test_ids_belong_to_clause_10 if {
	count({id | some id, _ in mod.items; not startswith(id, "10.")}) == 0
}

# ── Fail-closed ─────────────────────────────────────────────────────────────

test_empty_input_fails_every_row if {
	r := mod.compliance_report with input as {}
	r.compliant == false
	r.passed == 0
	r.failed == 4
	r.violation_count == 4
	r.gaps == sort([id | some id, _ in mod.items])
}

test_full_fixture_passes if {
	r := mod.compliance_report with input as fx.full
	r.compliant == true
	r.passed == 4
	r.failed == 0
	r.violation_count == 0
	r.attested == 2
	r.fact_evaluated == 2
	r.fact_passed == 2
	r.gaps == []
}

test_report_shape if {
	r := mod.compliance_report with input as {}
	r.framework == "SAE AS9100D (9100:2016)"
	r.clause == "10"
	r.name == "Improvement"
	r.total == 4
	r.attestation_items == 2
	r.fact_items == 2
	is_set(r.violations)
}

test_every_fact_row_names_its_evidence if {
	count({id | some id, it in mod.items; it.kind == "fact"; not is_string(it.evidence)}) == 0
}

test_string_true_is_not_an_attestation if {
	some id, it in mod.items
	it.kind == "attestation"
	inp := fx.with_patch(concat("/", ["attestations", id]), "true")
	not mod.passed[id] with input as inp
}

# ── Per-row cases ───────────────────────────────────────────────────────────

test_10_1_passes_when_attested if {
	mod.passed["10.1"] with input as fx.full
}

test_10_1_fails_when_not_attested if {
	inp := fx.without_attestation("10.1")
	not mod.passed["10.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 10.1: ")
	contains(msg, "not attested")
}

test_10_2_1_passes_on_full_evidence if {
	mod.passed["10.2.1"] with input as fx.full
}

test_10_2_1_fails_closed_without_evidence if {
	inp := fx.without_evidence("corrective_actions")
	not mod.passed["10.2.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 10.2.1: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.corrective_actions")
}

test_10_2_1_fails_on_bad_evidence if {
	inp := fx.with_patch("corrective_actions", {"records": [{
		"id": "CA-1",
		"nonconformity_id": "NCR-1",
		"root_cause": " ",
		"human_factors_considered": true,
		"status": "closed",
		"effectiveness_reviewed": true,
	}]})
	not mod.passed["10.2.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 10.2.1: ")
	contains(msg, "no root cause")
}

test_10_2_2_passes_on_full_evidence if {
	mod.passed["10.2.2"] with input as fx.full
}

test_10_2_2_fails_closed_without_evidence if {
	inp := fx.without_evidence("corrective_actions")
	not mod.passed["10.2.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 10.2.2: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.corrective_actions")
}

test_10_2_2_fails_on_bad_evidence if {
	inp := fx.with_patch("corrective_actions", {"records": [{
		"id": "CA-2",
		"nonconformity_id": "NCR-2",
		"root_cause": "tooling",
		"human_factors_considered": true,
		"status": "closed",
	}]})
	not mod.passed["10.2.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 10.2.2: ")
	contains(msg, "no effectiveness review")
}

test_10_3_passes_when_attested if {
	mod.passed["10.3"] with input as fx.full
}

test_10_3_fails_when_not_attested if {
	inp := fx.without_attestation("10.3")
	not mod.passed["10.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 10.3: ")
	contains(msg, "not attested")
}
