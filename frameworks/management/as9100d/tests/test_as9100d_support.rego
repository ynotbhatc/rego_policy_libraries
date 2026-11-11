# Tests for as9100d.support — SAE AS9100D clause 7 (Support): one pass and one fail case per row,
# evidence-missing and failing-evidence cases for every fact-decided row, generated from the clause table.
package as9100d.support_test

import rego.v1

import data.as9100d.support as mod
import data.as9100d_fixture_test as fx

# ── Table integrity ─────────────────────────────────────────────────────────

test_table_has_13_rows if {
	count(mod.items) == 13
	count({id | some id, it in mod.items; it.kind == "attestation"}) == 11
	count({id | some id, it in mod.items; it.kind == "fact"}) == 2
}

test_ids_belong_to_clause_7 if {
	count({id | some id, _ in mod.items; not startswith(id, "7.")}) == 0
}

# ── Fail-closed ─────────────────────────────────────────────────────────────

test_empty_input_fails_every_row if {
	r := mod.compliance_report with input as {}
	r.compliant == false
	r.passed == 0
	r.failed == 13
	r.violation_count == 13
	r.gaps == sort([id | some id, _ in mod.items])
}

test_full_fixture_passes if {
	r := mod.compliance_report with input as fx.full
	r.compliant == true
	r.passed == 13
	r.failed == 0
	r.violation_count == 0
	r.attested == 11
	r.fact_evaluated == 2
	r.fact_passed == 2
	r.gaps == []
}

test_report_shape if {
	r := mod.compliance_report with input as {}
	r.framework == "SAE AS9100D (9100:2016)"
	r.clause == "7"
	r.name == "Support"
	r.total == 13
	r.attestation_items == 11
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

test_7_1_1_passes_when_attested if {
	mod.passed["7.1.1"] with input as fx.full
}

test_7_1_1_fails_when_not_attested if {
	inp := fx.without_attestation("7.1.1")
	not mod.passed["7.1.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.1.1: ")
	contains(msg, "not attested")
}

test_7_1_2_passes_when_attested if {
	mod.passed["7.1.2"] with input as fx.full
}

test_7_1_2_fails_when_not_attested if {
	inp := fx.without_attestation("7.1.2")
	not mod.passed["7.1.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.1.2: ")
	contains(msg, "not attested")
}

test_7_1_3_passes_when_attested if {
	mod.passed["7.1.3"] with input as fx.full
}

test_7_1_3_fails_when_not_attested if {
	inp := fx.without_attestation("7.1.3")
	not mod.passed["7.1.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.1.3: ")
	contains(msg, "not attested")
}

test_7_1_4_passes_when_attested if {
	mod.passed["7.1.4"] with input as fx.full
}

test_7_1_4_fails_when_not_attested if {
	inp := fx.without_attestation("7.1.4")
	not mod.passed["7.1.4"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.1.4: ")
	contains(msg, "not attested")
}

test_7_1_5_1_passes_on_full_evidence if {
	mod.passed["7.1.5.1"] with input as fx.full
}

test_7_1_5_1_fails_closed_without_evidence if {
	inp := fx.without_evidence("measuring_equipment")
	not mod.passed["7.1.5.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 7.1.5.1: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.measuring_equipment")
}

test_7_1_5_1_fails_on_bad_evidence if {
	inp := fx.with_patch("measuring_equipment", [{
		"id": "CMM-01",
		"in_service": true,
		"traceable": true,
	}])
	not mod.passed["7.1.5.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 7.1.5.1: ")
	contains(msg, "no calibration due date")
}

test_7_1_5_2_passes_on_full_evidence if {
	mod.passed["7.1.5.2"] with input as fx.full
}

test_7_1_5_2_fails_closed_without_evidence if {
	inp := fx.without_evidence("measuring_equipment")
	not mod.passed["7.1.5.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 7.1.5.2: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.measuring_equipment")
}

test_7_1_5_2_fails_on_bad_evidence if {
	inp := fx.with_patch("measuring_equipment", [{
		"id": "CMM-01",
		"in_service": true,
		"calibration_due": "2026-10-01",
		"traceable": true,
	}])
	not mod.passed["7.1.5.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 7.1.5.2: ")
	contains(msg, "is overdue")
}

test_7_1_6_passes_when_attested if {
	mod.passed["7.1.6"] with input as fx.full
}

test_7_1_6_fails_when_not_attested if {
	inp := fx.without_attestation("7.1.6")
	not mod.passed["7.1.6"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.1.6: ")
	contains(msg, "not attested")
}

test_7_2_passes_when_attested if {
	mod.passed["7.2"] with input as fx.full
}

test_7_2_fails_when_not_attested if {
	inp := fx.without_attestation("7.2")
	not mod.passed["7.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.2: ")
	contains(msg, "not attested")
}

test_7_3_passes_when_attested if {
	mod.passed["7.3"] with input as fx.full
}

test_7_3_fails_when_not_attested if {
	inp := fx.without_attestation("7.3")
	not mod.passed["7.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.3: ")
	contains(msg, "not attested")
}

test_7_4_passes_when_attested if {
	mod.passed["7.4"] with input as fx.full
}

test_7_4_fails_when_not_attested if {
	inp := fx.without_attestation("7.4")
	not mod.passed["7.4"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.4: ")
	contains(msg, "not attested")
}

test_7_5_1_passes_when_attested if {
	mod.passed["7.5.1"] with input as fx.full
}

test_7_5_1_fails_when_not_attested if {
	inp := fx.without_attestation("7.5.1")
	not mod.passed["7.5.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.5.1: ")
	contains(msg, "not attested")
}

test_7_5_2_passes_when_attested if {
	mod.passed["7.5.2"] with input as fx.full
}

test_7_5_2_fails_when_not_attested if {
	inp := fx.without_attestation("7.5.2")
	not mod.passed["7.5.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.5.2: ")
	contains(msg, "not attested")
}

test_7_5_3_passes_when_attested if {
	mod.passed["7.5.3"] with input as fx.full
}

test_7_5_3_fails_when_not_attested if {
	inp := fx.without_attestation("7.5.3")
	not mod.passed["7.5.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 7.5.3: ")
	contains(msg, "not attested")
}
