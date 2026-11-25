# Tests for aca_155_260.main — 45 CFR 155.260 privacy and security of PII.
package aca_155_260.main_test

import rego.v1

import data.aca_155_260.main

_all := {id: true | some id, _ in main.obligations}

_nee := {id: true | some id, r in main.obligations; "non_exchange_entity" in r.applies_to}

test_row_counts_pinned if {
	count(main.obligations_list) == 35
	count(main.obligations) == 35
	count({id | some id, r in main.obligations; r.section == "(a)"}) == 19
	count({id | some id, r in main.obligations; r.section == "(b)"}) == 8
	count({id | some id, r in main.obligations; startswith(id, "155.260(a)(3)(")}) == 8
	count(_nee) == 5
	main.compliance_report.standard_total == 35 with input as {}
}

test_every_row_has_known_section_and_role if {
	count({id | some id, r in main.obligations; not main.sections[r.section]}) == 0
	count({id | some id, r in main.obligations; some x in r.applies_to; not x in main.roles}) == 0
	count({id | some id, r in main.obligations; not startswith(id, concat("", ["155.260", r.section]))}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.role == "undeclared"
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# FAIL-CLOSED + undeclared role; no row is evaluated without a role
	r.violation_count == 2
}

test_exchange_all_true_is_compliant if {
	inp := {"aca_155_260": {"exchange_or_non_exchange_entity": "exchange", "obligations": _all}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.rows_evaluated == 35
	r.paragraphs["(a)"].rows_attested == 19
}

test_non_exchange_entity_needs_five if {
	inp := {"aca_155_260": {"exchange_or_non_exchange_entity": "non_exchange_entity", "obligations": _nee}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.rows_evaluated == 5
	r.paragraphs["(a)"].rows_evaluated == 0
}

test_non_exchange_entity_empty_lists_gaps if {
	r := main.compliance_report with input as {"aca_155_260": {"exchange_or_non_exchange_entity": "non_exchange_entity", "obligations": {}}}
	r.paragraphs["(b)"].gaps == ["155.260(b)(2)(ii)", "155.260(b)(2)(iii)", "155.260(b)(2)(iv)", "155.260(b)(2)(v)"]
	r.paragraphs["(f)"].gaps == ["155.260(f)"]
	r.violation_count == 5
}

test_one_false_is_named if {
	inp := {"aca_155_260": {"exchange_or_non_exchange_entity": "exchange", "obligations": object.union(_all, {"155.260(a)(5)": false})}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "45 CFR 155.260(a)(5)")
}

test_invalid_role_and_unknown_id if {
	inp := {"aca_155_260": {"exchange_or_non_exchange_entity": "broker", "obligations": object.union(_all, {"155.260(g)": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "must be declared")
	some m2 in v
	contains(m2, "unknown id 155.260(g)")
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"aca_155_260": {"exchange_or_non_exchange_entity": "exchange", "obligations": "all"}}
	some m in v
	contains(m, "FAIL-CLOSED")
}

# ── Evidence rule (data-driven, audit 2026-11-24) ────────────────────────────────────────────────────
# Only the boolean true passes a yes/no fact, and a scope flag must be a declared boolean. Every boolean in
# the widest all-pass fixture is replaced in turn by a wrong-typed value, by null, and removed: none passes.
# The report is also defined and non-compliant when there is no input or the module's container is not an object.

_evidence_full := {"aca_155_260": {"exchange_or_non_exchange_entity": "exchange", "obligations": _all}}

_evidence_bool_paths := [p | walk(_evidence_full, [p, v]); is_boolean(v)]

test_evidence_fixture_passes if {
	r := main.compliance_report with input as _evidence_full
	r.compliant == true
	r.violation_count == 0
	count(_evidence_bool_paths) > 10
}

test_evidence_wrong_type_or_null_never_passes if {
	every p in _evidence_bool_paths {
		every bad in ["false", "true", "no", 0, 1, null] {
			r := main.compliance_report with input as json.patch(_evidence_full, [{"op": "replace", "path": p, "value": bad}])
			r.compliant == false
			r.violation_count >= 1
		}
	}
}

test_evidence_removed_never_passes if {
	every p in _evidence_bool_paths {
		r := main.compliance_report with input as json.remove(_evidence_full, [concat("/", p)])
		r.compliant == false
		r.violation_count >= 1
	}
}

test_evidence_report_defined_on_no_or_non_object_facts if {
	some key, _ in _evidence_full
	every bad in [null, "true", "1", 1, true, []] {
		r := main.compliance_report with input as {key: bad}
		r.compliant == false
		r.violation_count >= 1
		top := main.compliance_report with input as bad
		top.compliant == false
	}
	empty := main.compliance_report with input as {}
	empty.compliant == false
}

test_evidence_problem_is_named if {
	some id, _ in _all
	r1 := main.compliance_report with input as json.patch(_evidence_full, [{"op": "replace", "path": ["aca_155_260", "obligations", id], "value": "true"}])
	r1.violation_count == 1
	some v1 in r1.violations
	contains(v1, "[evidence invalid — attestation is not a boolean (got string)]")
	r2 := main.compliance_report with input as json.remove(_evidence_full, [concat("/", ["aca_155_260", "obligations", id])])
	r2.violation_count == 1
	some v2 in r2.violations
	contains(v2, "[evidence missing — attestation not collected]")
	r3 := main.compliance_report with input as json.patch(_evidence_full, [{"op": "replace", "path": ["aca_155_260", "obligations", id], "value": false}])
	r3.violation_count == 1
	some v3 in r3.violations
	not contains(v3, "[evidence")
}
