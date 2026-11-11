# Tests for as9100d.performance — SAE AS9100D clause 9 (Performance evaluation): one pass and one fail case per row,
# evidence-missing and failing-evidence cases for every fact-decided row, generated from the clause table.
package as9100d.performance_test

import rego.v1

import data.as9100d.performance as mod
import data.as9100d_fixture_test as fx

# ── Table integrity ─────────────────────────────────────────────────────────

test_table_has_8_rows if {
	count(mod.items) == 8
	count({id | some id, it in mod.items; it.kind == "attestation"}) == 4
	count({id | some id, it in mod.items; it.kind == "fact"}) == 4
}

test_ids_belong_to_clause_9 if {
	count({id | some id, _ in mod.items; not startswith(id, "9.")}) == 0
}

# ── Fail-closed ─────────────────────────────────────────────────────────────

test_empty_input_fails_every_row if {
	r := mod.compliance_report with input as {}
	r.compliant == false
	r.passed == 0
	r.failed == 8
	r.violation_count == 8
	r.gaps == sort([id | some id, _ in mod.items])
}

test_full_fixture_passes if {
	r := mod.compliance_report with input as fx.full
	r.compliant == true
	r.passed == 8
	r.failed == 0
	r.violation_count == 0
	r.attested == 4
	r.fact_evaluated == 4
	r.fact_passed == 4
	r.gaps == []
}

test_report_shape if {
	r := mod.compliance_report with input as {}
	r.framework == "SAE AS9100D (9100:2016)"
	r.clause == "9"
	r.name == "Performance evaluation"
	r.total == 8
	r.attestation_items == 4
	r.fact_items == 4
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

test_9_1_1_passes_when_attested if {
	mod.passed["9.1.1"] with input as fx.full
}

test_9_1_1_fails_when_not_attested if {
	inp := fx.without_attestation("9.1.1")
	not mod.passed["9.1.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 9.1.1: ")
	contains(msg, "not attested")
}

test_9_1_2_passes_on_full_evidence if {
	mod.passed["9.1.2"] with input as fx.full
}

test_9_1_2_fails_closed_without_evidence if {
	inp := fx.without_evidence("kpis")
	not mod.passed["9.1.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 9.1.2: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.kpis")
}

test_9_1_2_fails_on_bad_evidence if {
	inp := fx.with_patch("kpis", {
		"on_time_delivery": {
			"value": 90,
			"target": 95,
			"period_end": "2026-10-31",
		},
		"conformity": {
			"value": 99,
			"target": 98,
			"period_end": "2026-10-31",
		},
	})
	not mod.passed["9.1.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 9.1.2: ")
	contains(msg, "against a target of 95")
}

test_9_1_3_passes_when_attested if {
	mod.passed["9.1.3"] with input as fx.full
}

test_9_1_3_fails_when_not_attested if {
	inp := fx.without_attestation("9.1.3")
	not mod.passed["9.1.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 9.1.3: ")
	contains(msg, "not attested")
}

test_9_2_1_passes_on_full_evidence if {
	mod.passed["9.2.1"] with input as fx.full
}

test_9_2_1_fails_closed_without_evidence if {
	inp := fx.without_evidence("internal_audit")
	not mod.passed["9.2.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 9.2.1: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.internal_audit")
}

test_9_2_1_fails_on_bad_evidence if {
	inp := fx.with_patch("internal_audit", {
		"programme": {"planned": [{
			"id": "IA-1",
			"scope": "all",
		}]},
		"audits": [{
			"id": "IA-0",
			"completed_on": "2025-02-01",
			"report_issued": true,
		}],
	})
	not mod.passed["9.2.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 9.2.1: ")
	contains(msg, "no internal audit was completed within the past year")
}

test_9_2_2_passes_on_full_evidence if {
	mod.passed["9.2.2"] with input as fx.full
}

test_9_2_2_fails_closed_without_evidence if {
	inp := fx.without_evidence("internal_audit")
	not mod.passed["9.2.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 9.2.2: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.internal_audit")
}

test_9_2_2_fails_on_bad_evidence if {
	inp := fx.with_patch("internal_audit", {
		"programme": {"planned": []},
		"audits": [{
			"id": "IA-1",
			"completed_on": "2026-03-20",
			"report_issued": true,
		}],
	})
	not mod.passed["9.2.2"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 9.2.2: ")
	contains(msg, "no planned audits")
}

test_9_3_1_passes_on_full_evidence if {
	mod.passed["9.3.1"] with input as fx.full
}

test_9_3_1_fails_closed_without_evidence if {
	inp := fx.without_evidence("management_review")
	not mod.passed["9.3.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 9.3.1: ")
	contains(msg, "FAIL-CLOSED: no evidence at input.as9100d.management_review")
}

test_9_3_1_fails_on_bad_evidence if {
	inp := fx.with_patch("management_review", {"reviews": [{
		"held_on": "2025-06-15",
		"outputs_recorded": true,
	}]})
	not mod.passed["9.3.1"] with input as inp
	v := mod.violations with input as inp
	some msg in v
	startswith(msg, "AS9100D 9.3.1: ")
	contains(msg, "no management review was held within the past year")
}

test_9_3_2_passes_when_attested if {
	mod.passed["9.3.2"] with input as fx.full
}

test_9_3_2_fails_when_not_attested if {
	inp := fx.without_attestation("9.3.2")
	not mod.passed["9.3.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 9.3.2: ")
	contains(msg, "not attested")
}

test_9_3_3_passes_when_attested if {
	mod.passed["9.3.3"] with input as fx.full
}

test_9_3_3_fails_when_not_attested if {
	inp := fx.without_attestation("9.3.3")
	not mod.passed["9.3.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 9.3.3: ")
	contains(msg, "not attested")
}
