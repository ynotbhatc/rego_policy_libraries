# Tests for as9100d.leadership — SAE AS9100D clause 5 (Leadership): one pass and one fail case per row,
# evidence-missing and failing-evidence cases for every fact-decided row, generated from the clause table.
package as9100d.leadership_test

import rego.v1

import data.as9100d.leadership as mod
import data.as9100d_fixture_test as fx

# ── Table integrity ─────────────────────────────────────────────────────────

test_table_has_5_rows if {
	count(mod.items) == 5
	count({id | some id, it in mod.items; it.kind == "attestation"}) == 5
	count({id | some id, it in mod.items; it.kind == "fact"}) == 0
}

test_ids_belong_to_clause_5 if {
	count({id | some id, _ in mod.items; not startswith(id, "5.")}) == 0
}

# ── Fail-closed ─────────────────────────────────────────────────────────────

test_empty_input_fails_every_row if {
	r := mod.compliance_report with input as {}
	r.compliant == false
	r.passed == 0
	r.failed == 5
	r.violation_count == 5
	r.gaps == sort([id | some id, _ in mod.items])
}

test_full_fixture_passes if {
	r := mod.compliance_report with input as fx.full
	r.compliant == true
	r.passed == 5
	r.failed == 0
	r.violation_count == 0
	r.attested == 5
	r.fact_evaluated == 0
	r.fact_passed == 0
	r.gaps == []
}

test_report_shape if {
	r := mod.compliance_report with input as {}
	r.framework == "SAE AS9100D (9100:2016)"
	r.clause == "5"
	r.name == "Leadership"
	r.total == 5
	r.attestation_items == 5
	r.fact_items == 0
	is_set(r.violations)
}

test_string_true_is_not_an_attestation if {
	some id, it in mod.items
	it.kind == "attestation"
	inp := fx.with_patch(concat("/", ["attestations", id]), "true")
	not mod.passed[id] with input as inp
}

# ── Per-row cases ───────────────────────────────────────────────────────────

test_5_1_1_passes_when_attested if {
	mod.passed["5.1.1"] with input as fx.full
}

test_5_1_1_fails_when_not_attested if {
	inp := fx.without_attestation("5.1.1")
	not mod.passed["5.1.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 5.1.1: ")
	contains(msg, "not attested")
}

test_5_1_2_passes_when_attested if {
	mod.passed["5.1.2"] with input as fx.full
}

test_5_1_2_fails_when_not_attested if {
	inp := fx.without_attestation("5.1.2")
	not mod.passed["5.1.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 5.1.2: ")
	contains(msg, "not attested")
}

test_5_2_1_passes_when_attested if {
	mod.passed["5.2.1"] with input as fx.full
}

test_5_2_1_fails_when_not_attested if {
	inp := fx.without_attestation("5.2.1")
	not mod.passed["5.2.1"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 5.2.1: ")
	contains(msg, "not attested")
}

test_5_2_2_passes_when_attested if {
	mod.passed["5.2.2"] with input as fx.full
}

test_5_2_2_fails_when_not_attested if {
	inp := fx.without_attestation("5.2.2")
	not mod.passed["5.2.2"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 5.2.2: ")
	contains(msg, "not attested")
}

test_5_3_passes_when_attested if {
	mod.passed["5.3"] with input as fx.full
}

test_5_3_fails_when_not_attested if {
	inp := fx.without_attestation("5.3")
	not mod.passed["5.3"] with input as inp
	v := mod.violations with input as inp
	count(v) == 1
	some msg in v
	startswith(msg, "AS9100D 5.3: ")
	contains(msg, "not attested")
}
