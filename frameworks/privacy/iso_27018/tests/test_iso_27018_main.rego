# Tests for iso_27018.main (ISO/IEC 27018:2019, Annex A). The counts below are the standard's own, from DIN's public table of
# contents of the 2019 edition: 25 controls, A.2.1 to A.12.2, in 8 groups.

package iso_27018.main_test

import data.iso_27018.index
import data.iso_27018.main
import rego.v1

_all_true := {id: true | some id in index.order}

_inp(x) := {"iso_27018": x}

_good_body := {"public_cloud_pii_processor": true, "iso27001_isms_in_place": true, "controls": _all_true}

# replace whole top-level fields (object.union would merge the controls objects and put a removed control back)
_with(o) := object.union(object.remove(_good_body, object.keys(o)), o)

# the all-pass fixture
good_processor := _inp(_good_body)

# the same facts with two controls marked not applicable, each with a reason and no result
good_processor_with_not_applicable := _inp(_with({
	"controls": object.remove(_all_true, ["A.11.2", "A.11.7"]),
	"not_applicable": {"A.11.2": "no hardcopy is created", "A.11.7": "no hardcopy exists"},
}))

_r(inp) := r if {
	r := main.compliance_report with input as inp
}

_identity(r) if (r.passed_controls + r.failed_controls) + r.not_applicable_controls == r.total_controls

_controls_with(overrides) := _inp(_with({"controls": object.union(_all_true, overrides)}))

_without(id) := _inp(_with({"controls": object.remove(_all_true, [id])}))

_status(r, id) := s if {
	some c in r.control_results
	c.id == id
	s := c.status
}

# ── the index ────────────────────────────────────────────────────────────────

test_index_counts if {
	count(index.order) == 25
	count(index.labels) == 25
	count(index.groups) == 25
	count(index.group_labels) == 8
	count({g | some _, g in index.groups}) == 8
	sum([count(m) | some _, m in index.by_group]) == 25
	count(index.CONTROL_INDEX) == 25
}

test_index_ids_are_the_annex_a_controls_of_the_2019_edition if {
	index.order == [
		"A.2.1", "A.3.1", "A.3.2", "A.5.1", "A.6.1", "A.6.2", "A.8.1", "A.10.1", "A.10.2", "A.10.3",
		"A.11.1", "A.11.2", "A.11.3", "A.11.4", "A.11.5", "A.11.6", "A.11.7", "A.11.8", "A.11.9", "A.11.10", "A.11.11", "A.11.12", "A.11.13",
		"A.12.1", "A.12.2",
	]
}

test_group_sizes_match_the_standard if {
	{g: count(m) | some g, m in index.by_group} == {"A.2": 1, "A.3": 2, "A.5": 1, "A.6": 2, "A.8": 1, "A.10": 3, "A.11": 13, "A.12": 2}
}

test_report_total_equals_index if {
	r := _r(good_processor)
	r.total_controls == count(index.order)
	r.total_controls == 25
}

# ── empty and missing input ──────────────────────────────────────────────────

test_empty_input_is_not_compliant if {
	r := _r({})
	r.compliant == false
	r.total_controls == 25
	r.passed_controls == 0
	r.failed_controls == 25
	r.not_applicable_controls == 0
	r.applicable == true
	_identity(r)
	count(r.violations) >= 25
}

test_empty_object_under_the_key_is_not_compliant if {
	r := _r(_inp({}))
	r.compliant == false
	r.failed_controls == 25
}

test_input_of_other_type_is_not_compliant if {
	every bad in ["x", 1, null, true, []] {
		r := _r(_inp(bad))
		r.compliant == false
		r.failed_controls == 25
	}
}

# ── all-pass ─────────────────────────────────────────────────────────────────

test_all_pass_is_compliant if {
	r := _r(good_processor)
	r.compliant == true
	r.passed_controls == 25
	r.failed_controls == 0
	r.not_applicable_controls == 0
	r.violation_count == 0
	r.base_isms_attested == true
	_identity(r)
}

test_all_pass_with_two_not_applicable if {
	r := _r(good_processor_with_not_applicable)
	r.compliant == true
	r.passed_controls == 23
	r.not_applicable_controls == 2
	r.not_applicable_ids == ["A.11.2", "A.11.7"]
	_identity(r)
}

test_group_results_add_up if {
	r := _r(good_processor_with_not_applicable)
	sum([g.total | some g in r.group_results]) == 25
	sum([g.passed | some g in r.group_results]) == 23
	sum([g.not_applicable | some g in r.group_results]) == 2
	sum([g.failed | some g in r.group_results]) == 0
}

# ── the statement that the organization is a public cloud PII processor ──────

test_processor_missing_is_a_finding_and_all_controls_are_assessed if {
	r := _r(_inp(object.remove(_good_body, ["public_cloud_pii_processor"])))
	r.compliant == false
	r.applicable == true
	r.passed_controls == 25
	r.violation_count == 1
	_identity(r)
}

test_processor_wrong_type_is_a_finding if {
	every bad in ["true", "false", "yes", 1, 0, null, [], {}] {
		r := _r(_inp(_with({"public_cloud_pii_processor": bad})))
		r.compliant == false
		r.applicable == true
		r.passed_controls == 25
		r.not_applicable_controls == 0
	}
}

test_processor_false_with_reason_reports_every_control_not_applicable if {
	r := _r(_inp({"public_cloud_pii_processor": false, "not_applicable_reason": "we only provide software the customer runs itself"}))
	r.applicable == false
	r.compliant == false
	r.total_controls == 25
	r.not_applicable_controls == 25
	r.passed_controls == 0
	r.failed_controls == 0
	r.violation_count == 0
	r.not_applicable_reason == "we only provide software the customer runs itself"
	_identity(r)
}

test_processor_false_ignores_results_and_the_isms_attestation if {
	r := _r(_inp(_with({"public_cloud_pii_processor": false, "iso27001_isms_in_place": false, "not_applicable_reason": "not a processor"})))
	r.applicable == false
	r.not_applicable_controls == 25
	r.violation_count == 0
	r.compliant == false
}

test_processor_false_needs_a_reason if {
	every bad in [null, "", "   ", 1, true, []] {
		r := _r(_inp({"public_cloud_pii_processor": false, "not_applicable_reason": bad}))
		r.applicable == false
		r.compliant == false
		r.violation_count == 1
		r.not_applicable_controls == 25
	}
	r := _r(_inp({"public_cloud_pii_processor": false}))
	r.violation_count == 1
}

# ── the link to the ISO/IEC 27001 ISMS ───────────────────────────────────────

test_isms_missing_is_a_finding if {
	r := _r(_inp(object.remove(_good_body, ["iso27001_isms_in_place"])))
	r.compliant == false
	r.base_isms_attested == false
	r.passed_controls == 25
	r.violation_count == 1
	_identity(r)
}

test_isms_false_null_and_strings_are_findings if {
	every bad in [false, null, "true", "false", "yes", 1, 0, [], {}] {
		r := _r(_inp(_with({"iso27001_isms_in_place": bad})))
		r.compliant == false
		r.base_isms_attested == false
		r.passed_controls == 25
		r.violation_count == 1
	}
}

# ── each control: false, strings, null, removed (five slices so each test stays small) ──

_slice(lo, hi) := [id | some i, id in index.order; i >= lo; i < hi]

_check_control(id) if {
	f := _r(_controls_with({id: false}))
	f.compliant == false
	f.failed_controls == 1
	f.failed_control_ids == [id]
	_status(f, id) == "fail"
	_identity(f)

	every bad in ["true", "false", "yes", "no", 1, 0, [], {}] {
		r := _r(_controls_with({id: bad}))
		r.compliant == false
		r.failed_controls == 1
		_status(r, id) == "evidence_invalid"
		some m in r.violations
		contains(m, id)
		contains(m, "is not a boolean")
	}

	n := _r(_controls_with({id: null}))
	n.compliant == false
	_status(n, id) == "evidence_missing"
	contains(n.control_results[index_of(id)].findings[0], "is null")

	g := _r(_without(id))
	g.compliant == false
	g.failed_controls == 1
	_status(g, id) == "evidence_missing"
	contains(g.control_results[index_of(id)].findings[0], "not collected")
	_identity(g)
}

index_of(id) := i if {
	some i, x in index.order
	x == id
}

test_every_control_slice_1 if {
	every id in _slice(0, 5) { _check_control(id) }
}

test_every_control_slice_2 if {
	every id in _slice(5, 10) { _check_control(id) }
}

test_every_control_slice_3 if {
	every id in _slice(10, 15) { _check_control(id) }
}

test_every_control_slice_4 if {
	every id in _slice(15, 20) { _check_control(id) }
}

test_every_control_slice_5 if {
	every id in _slice(20, 25) { _check_control(id) }
}

test_slices_cover_the_index if {
	array.concat(array.concat(array.concat(_slice(0, 5), _slice(5, 10)), array.concat(_slice(10, 15), _slice(15, 20))), _slice(20, 25)) == index.order
}

# ── findings name the field ──────────────────────────────────────────────────

test_findings_name_the_field_and_the_control if {
	r := _r(_without("A.11.6"))
	r.violations == {"ISO/IEC 27018 A.11.6: evidence missing: input.iso_27018.controls[\"A.11.6\"] not collected (Encryption on public networks)"}
}

test_failed_is_counted_not_clamped if {
	r := _r(_inp({"public_cloud_pii_processor": true}))
	r.failed_controls == 25
	r.passed_controls == 0
	_identity(r)
}

# ── not applicable ───────────────────────────────────────────────────────────

test_not_applicable_needs_a_reason if {
	every bad in ["", "   ", null, 1, true, [], {}] {
		inp := _inp(_with({
			"controls": object.remove(_all_true, ["A.11.2"]),
			"not_applicable": {"A.11.2": bad},
		}))
		r := _r(inp)
		r.compliant == false
		r.not_applicable_controls == 0
		r.failed_controls == 1
		_status(r, "A.11.2") == "evidence_invalid"
		_identity(r)
	}
}

test_not_applicable_beside_a_result_is_a_finding if {
	inp := _inp(_with({"not_applicable": {"A.11.2": "no hardcopy"}}))
	r := _r(inp)
	r.compliant == false
	r.failed_controls == 1
	r.not_applicable_controls == 0
	_status(r, "A.11.2") == "evidence_invalid"
	some m in r.violations
	contains(m, "not both")
}

test_absence_of_a_result_is_never_not_applicable if {
	r := _r(_without("A.12.2"))
	r.not_applicable_controls == 0
	r.failed_controls == 1
}

test_all_not_applicable_is_not_compliant if {
	inp := _inp({
		"public_cloud_pii_processor": true,
		"iso27001_isms_in_place": true,
		"not_applicable": {id: "reason" | some id in index.order},
	})
	r := _r(inp)
	r.compliant == false
	r.not_applicable_controls == 25
	r.passed_controls == 0
	r.violation_count == 0
	_identity(r)
}

# ── unknown ids and containers ───────────────────────────────────────────────

test_unknown_ids_are_reported if {
	inp := _inp(_with({
		"controls": object.union(_all_true, {"A.4.1": true, "A.13.1": true, "A.11.14": true, "A.1.1": true}),
		"not_applicable": {"A.9.1": "none"},
	}))
	r := _r(inp)
	r.compliant == false
	r.violation_count == 5
	r.passed_controls == 25
	some m in r.violations
	contains(m, "\"A.9.1\"] is not a control id")
}

test_ids_of_the_2013_style_and_without_prefix_are_unknown if {
	r := _r(_controls_with({"11.1": true, "a.11.1": true, "A.11.1 ": true}))
	r.violation_count == 3
}

test_containers_of_the_wrong_type_are_findings if {
	r := _r(_inp(_with({"controls": ["A.11.1"]})))
	r.compliant == false
	r.failed_controls == 25
	r2 := _r(_inp(_with({"not_applicable": "none"})))
	r2.compliant == false
	r2.passed_controls == 25
	r2.violation_count == 1
}

# ── the full report on a mixed input keeps the arithmetic ────────────────────

test_mixed_input_arithmetic if {
	inp := _inp({
		"public_cloud_pii_processor": true,
		"iso27001_isms_in_place": true,
		"controls": {"A.2.1": true, "A.3.1": false, "A.3.2": "true", "A.5.1": null, "A.6.1": true},
		"not_applicable": {"A.6.2": "no disclosure requests are possible", "A.11.1": ""},
	})
	r := _r(inp)
	r.total_controls == 25
	r.passed_controls == 2
	r.not_applicable_controls == 1
	r.failed_controls == 22
	r.control_result_counts == {"pass": 2, "fail": 1, "evidence_missing": 19, "evidence_invalid": 2, "not_applicable": 1}
	_identity(r)
	count(r.control_results) == 25
}
