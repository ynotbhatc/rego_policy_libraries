# Tests for as9100d.operation — SAE AS9100D clause 8 (Operation): one pass and one fail case per row,
# evidence-missing and failing-evidence cases for every fact-decided row, generated from the clause table.
package as9100d.operation_test

import rego.v1

import data.as9100d.operation as mod
import data.as9100d_fixture_test as fx

# ── Table integrity ─────────────────────────────────────────────────────────

test_table_has_31_rows if {
	count(mod.items) == 31
	count({id | some id, it in mod.items; it.kind == "attestation"}) == 21
	count({id | some id, it in mod.items; it.kind == "fact"}) == 10
}

test_ids_belong_to_clause_8 if {
	count({id | some id, _ in mod.items; not startswith(id, "8.")}) == 0
}

# ── Fail-closed ─────────────────────────────────────────────────────────────

test_empty_input_fails_every_row if {
	r := mod.compliance_report with input as {}
	r.compliant == false
	r.passed == 0
	r.failed == 31
	r.violation_count == 31
	r.gaps == sort([id | some id, _ in mod.items])
}

test_full_fixture_passes if {
	r := mod.compliance_report with input as fx.full
	r.compliant == true
	r.passed == 31
	r.failed == 0
	r.violation_count == 0
	r.attested == 21
	r.fact_evaluated == 10
	r.fact_passed == 10
	r.gaps == []
}

test_report_shape if {
	r := mod.compliance_report with input as {}
	r.framework == "SAE AS9100D (9100:2016)"
	r.clause == "8"
	r.name == "Operation"
	r.total == 31
	r.attestation_items == 21
	r.fact_items == 10
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

test_8_1_passes_when_attested if {
	mod.passed["8.1"] with input as fx.full
}

test_8_1_fails_when_not_attested if {
	inp := fx.without_attestation("8.1")
	not mod.passed["8.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.1: ")
	contains(msg, "not attested")
}

test_8_1_1_passes_when_attested if {
	mod.passed["8.1.1"] with input as fx.full
}

test_8_1_1_fails_when_not_attested if {
	inp := fx.without_attestation("8.1.1")
	not mod.passed["8.1.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.1.1: ")
	contains(msg, "not attested")
}

test_8_1_2_passes_on_full_evidence if {
	mod.passed["8.1.2"] with input as fx.full
}

test_8_1_2_fails_closed_without_evidence if {
	inp := fx.without_evidence("configuration_management")
	not mod.passed["8.1.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.1.2: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.configuration_management")
}

test_8_1_2_fails_on_bad_evidence if {
	inp := fx.with_patch("configuration_management", {
		"baselines": [{
			"id": "BL-1",
			"approved": false,
		}],
		"drift_records": [],
	})
	not mod.passed["8.1.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.1.2: ")
	contains(msg, "is not approved")
}

test_8_1_3_passes_when_attested if {
	mod.passed["8.1.3"] with input as fx.full
}

test_8_1_3_fails_when_not_attested if {
	inp := fx.without_attestation("8.1.3")
	not mod.passed["8.1.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.1.3: ")
	contains(msg, "not attested")
}

test_8_1_4_passes_on_full_evidence if {
	mod.passed["8.1.4"] with input as fx.full
}

test_8_1_4_fails_closed_without_evidence if {
	inp := fx.without_evidence("counterfeit_prevention")
	not mod.passed["8.1.4"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.1.4: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.counterfeit_prevention")
}

test_8_1_4_fails_on_bad_evidence if {
	inp := fx.with_patch("counterfeit_prevention", {
		"approved_sources": ["OEM-A"],
		"components": [{
			"id": "PN-9",
			"source": "BROKER-X",
			"provenance_documented": true,
		}],
	})
	not mod.passed["8.1.4"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.1.4: ")
	contains(msg, "not an approved source")
}

test_8_2_1_passes_when_attested if {
	mod.passed["8.2.1"] with input as fx.full
}

test_8_2_1_fails_when_not_attested if {
	inp := fx.without_attestation("8.2.1")
	not mod.passed["8.2.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.2.1: ")
	contains(msg, "not attested")
}

test_8_2_2_passes_when_attested if {
	mod.passed["8.2.2"] with input as fx.full
}

test_8_2_2_fails_when_not_attested if {
	inp := fx.without_attestation("8.2.2")
	not mod.passed["8.2.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.2.2: ")
	contains(msg, "not attested")
}

test_8_2_3_passes_when_attested if {
	mod.passed["8.2.3"] with input as fx.full
}

test_8_2_3_fails_when_not_attested if {
	inp := fx.without_attestation("8.2.3")
	not mod.passed["8.2.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.2.3: ")
	contains(msg, "not attested")
}

test_8_2_4_passes_when_attested if {
	mod.passed["8.2.4"] with input as fx.full
}

test_8_2_4_fails_when_not_attested if {
	inp := fx.without_attestation("8.2.4")
	not mod.passed["8.2.4"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.2.4: ")
	contains(msg, "not attested")
}

test_8_3_1_passes_when_attested if {
	mod.passed["8.3.1"] with input as fx.full
}

test_8_3_1_fails_when_not_attested if {
	inp := fx.without_attestation("8.3.1")
	not mod.passed["8.3.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.3.1: ")
	contains(msg, "not attested")
}

test_8_3_2_passes_when_attested if {
	mod.passed["8.3.2"] with input as fx.full
}

test_8_3_2_fails_when_not_attested if {
	inp := fx.without_attestation("8.3.2")
	not mod.passed["8.3.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.3.2: ")
	contains(msg, "not attested")
}

test_8_3_3_passes_when_attested if {
	mod.passed["8.3.3"] with input as fx.full
}

test_8_3_3_fails_when_not_attested if {
	inp := fx.without_attestation("8.3.3")
	not mod.passed["8.3.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.3.3: ")
	contains(msg, "not attested")
}

test_8_3_4_passes_when_attested if {
	mod.passed["8.3.4"] with input as fx.full
}

test_8_3_4_fails_when_not_attested if {
	inp := fx.without_attestation("8.3.4")
	not mod.passed["8.3.4"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.3.4: ")
	contains(msg, "not attested")
}

test_8_3_4_1_passes_when_attested if {
	mod.passed["8.3.4.1"] with input as fx.full
}

test_8_3_4_1_fails_when_not_attested if {
	inp := fx.without_attestation("8.3.4.1")
	not mod.passed["8.3.4.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.3.4.1: ")
	contains(msg, "not attested")
}

test_8_3_5_passes_when_attested if {
	mod.passed["8.3.5"] with input as fx.full
}

test_8_3_5_fails_when_not_attested if {
	inp := fx.without_attestation("8.3.5")
	not mod.passed["8.3.5"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.3.5: ")
	contains(msg, "not attested")
}

test_8_3_6_passes_when_attested if {
	mod.passed["8.3.6"] with input as fx.full
}

test_8_3_6_fails_when_not_attested if {
	inp := fx.without_attestation("8.3.6")
	not mod.passed["8.3.6"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.3.6: ")
	contains(msg, "not attested")
}

test_8_4_1_passes_on_full_evidence if {
	mod.passed["8.4.1"] with input as fx.full
}

test_8_4_1_fails_closed_without_evidence if {
	inp := fx.without_evidence("external_providers")
	not mod.passed["8.4.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.4.1: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.external_providers")
}

test_8_4_1_fails_on_bad_evidence if {
	inp := fx.with_patch("external_providers", {"suppliers": [{
		"id": "SUP-9",
		"status": "disapproved",
		"scope": "castings",
		"performance_reviewed_on": "2026-09-30",
		"flow_down_acknowledged": true,
	}]})
	not mod.passed["8.4.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.4.1: ")
	contains(msg, "not approved or conditional")
}

test_8_4_2_passes_on_full_evidence if {
	mod.passed["8.4.2"] with input as fx.full
}

test_8_4_2_fails_closed_without_evidence if {
	inp := fx.without_evidence("external_providers")
	not mod.passed["8.4.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.4.2: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.external_providers")
}

test_8_4_2_fails_on_bad_evidence if {
	inp := fx.with_patch("external_providers", {"suppliers": [{
		"id": "SUP-1",
		"status": "approved",
		"scope": "machined parts",
		"performance_reviewed_on": "2025-01-31",
		"flow_down_acknowledged": true,
	}]})
	not mod.passed["8.4.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.4.2: ")
	contains(msg, "no performance review within the past year")
}

test_8_4_3_passes_on_full_evidence if {
	mod.passed["8.4.3"] with input as fx.full
}

test_8_4_3_fails_closed_without_evidence if {
	inp := fx.without_evidence("external_providers")
	not mod.passed["8.4.3"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.4.3: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.external_providers")
}

test_8_4_3_fails_on_bad_evidence if {
	inp := fx.with_patch("external_providers", {"suppliers": [{
		"id": "SUP-1",
		"status": "approved",
		"scope": "machined parts",
		"performance_reviewed_on": "2026-09-30",
		"flow_down_acknowledged": false,
	}]})
	not mod.passed["8.4.3"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.4.3: ")
	contains(msg, "has not acknowledged")
}

test_8_5_1_passes_when_attested if {
	mod.passed["8.5.1"] with input as fx.full
}

test_8_5_1_fails_when_not_attested if {
	inp := fx.without_attestation("8.5.1")
	not mod.passed["8.5.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.5.1: ")
	contains(msg, "not attested")
}

test_8_5_1_1_passes_on_full_evidence if {
	mod.passed["8.5.1.1"] with input as fx.full
}

test_8_5_1_1_fails_closed_without_evidence if {
	inp := fx.without_evidence("production_equipment")
	not mod.passed["8.5.1.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.5.1.1: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.production_equipment")
}

test_8_5_1_1_fails_on_bad_evidence if {
	inp := fx.with_patch("production_equipment", [{
		"id": "NC-PROG-78",
		"type": "software",
		"validated": false,
	}])
	not mod.passed["8.5.1.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.5.1.1: ")
	contains(msg, "is not validated")
}

test_8_5_1_2_passes_when_attested if {
	mod.passed["8.5.1.2"] with input as fx.full
}

test_8_5_1_2_fails_when_not_attested if {
	inp := fx.without_attestation("8.5.1.2")
	not mod.passed["8.5.1.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.5.1.2: ")
	contains(msg, "not attested")
}

test_8_5_1_3_passes_when_attested if {
	mod.passed["8.5.1.3"] with input as fx.full
}

test_8_5_1_3_fails_when_not_attested if {
	inp := fx.without_attestation("8.5.1.3")
	not mod.passed["8.5.1.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.5.1.3: ")
	contains(msg, "not attested")
}

test_8_5_2_passes_on_full_evidence if {
	mod.passed["8.5.2"] with input as fx.full
}

test_8_5_2_fails_closed_without_evidence if {
	inp := fx.without_evidence("traceability")
	not mod.passed["8.5.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.5.2: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.traceability")
}

test_8_5_2_fails_on_bad_evidence if {
	inp := fx.with_patch("traceability", {"items": [{
		"id": "X-1",
		"part_number": "PN-100",
	}]})
	not mod.passed["8.5.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.5.2: ")
	contains(msg, "neither a serial nor a lot")
}

test_8_5_3_passes_when_attested if {
	mod.passed["8.5.3"] with input as fx.full
}

test_8_5_3_fails_when_not_attested if {
	inp := fx.without_attestation("8.5.3")
	not mod.passed["8.5.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.5.3: ")
	contains(msg, "not attested")
}

test_8_5_4_passes_when_attested if {
	mod.passed["8.5.4"] with input as fx.full
}

test_8_5_4_fails_when_not_attested if {
	inp := fx.without_attestation("8.5.4")
	not mod.passed["8.5.4"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.5.4: ")
	contains(msg, "not attested")
}

test_8_5_5_passes_when_attested if {
	mod.passed["8.5.5"] with input as fx.full
}

test_8_5_5_fails_when_not_attested if {
	inp := fx.without_attestation("8.5.5")
	not mod.passed["8.5.5"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.5.5: ")
	contains(msg, "not attested")
}

test_8_5_6_passes_on_full_evidence if {
	mod.passed["8.5.6"] with input as fx.full
}

test_8_5_6_fails_closed_without_evidence if {
	inp := fx.without_evidence("change_control")
	not mod.passed["8.5.6"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.5.6: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.change_control")
}

test_8_5_6_fails_on_bad_evidence if {
	inp := fx.with_patch("change_control", {"records": [{
		"id": "CR-13",
		"approved": true,
		"approved_by": "QA",
		"impact_reviewed": false,
	}]})
	not mod.passed["8.5.6"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.5.6: ")
	contains(msg, "no review of its consequences")
}

test_8_6_passes_when_attested if {
	mod.passed["8.6"] with input as fx.full
}

test_8_6_fails_when_not_attested if {
	inp := fx.without_attestation("8.6")
	not mod.passed["8.6"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 8.6: ")
	contains(msg, "not attested")
}

test_8_7_1_passes_on_full_evidence if {
	mod.passed["8.7.1"] with input as fx.full
}

test_8_7_1_fails_closed_without_evidence if {
	inp := fx.without_evidence("nonconformance")
	not mod.passed["8.7.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.7.1: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.nonconformance")
}

test_8_7_1_fails_on_bad_evidence if {
	inp := fx.with_patch("nonconformance", {"records": [{
		"id": "NCR-7",
		"description": "crack",
		"disposition": "use_as_is",
		"disposition_authority": "MRB",
	}]})
	not mod.passed["8.7.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.7.1: ")
	contains(msg, "without customer authorization")
}

test_8_7_2_passes_on_full_evidence if {
	mod.passed["8.7.2"] with input as fx.full
}

test_8_7_2_fails_closed_without_evidence if {
	inp := fx.without_evidence("nonconformance")
	not mod.passed["8.7.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.7.2: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.nonconformance")
}

test_8_7_2_fails_on_bad_evidence if {
	inp := fx.with_patch("nonconformance", {"records": [{
		"id": "NCR-8",
		"disposition": "scrap",
	}]})
	not mod.passed["8.7.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 8.7.2: ")
	contains(msg, "has no description")
}
