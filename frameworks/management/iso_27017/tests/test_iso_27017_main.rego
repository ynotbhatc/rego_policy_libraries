# Tests for iso_27017.main (ISO/IEC 27017:2026). The counts below are the standard's own, from the contents of the publisher's
# public preview of the second edition (2026-07): four additional cloud controls, 5.38, 5.39, 8.35 and 8.36.

package iso_27017.main_test

import data.iso_27017.index
import data.iso_27017.main
import rego.v1

_ids := ["5.38", "5.39", "8.35", "8.36"]

_cell(roles) := {r: true | some r in roles}

_all_true(roles) := {id: _cell(roles) | some id in _ids}

_body(role, roles) := {"role": role, "iso27001_isms_in_place": true, "controls": _all_true(roles)}

_inp(x) := {"iso_27017": x}

# the all-pass fixtures: each role, and both
good_customer := _inp(_body("customer", ["customer"]))

good_provider := _inp(_body("provider", ["provider"]))

good_both := _inp(_body("both", ["customer", "provider"]))

# both roles, one control and role not applicable (a reason, no result)
good_both_with_not_applicable := _inp(_with(_body("both", ["customer", "provider"]), {
	"controls": _with(_all_true(["customer", "provider"]), {"8.35": {"customer": true}}),
	"not_applicable": {"8.35": {"provider": "the organization does not operate virtual environments for others"}},
}))

_r(inp) := r if {
	r := main.compliance_report with input as inp
}

_identity(r) if (r.passed_controls + r.failed_controls) + r.not_applicable_controls == r.total_controls

# replace whole top-level fields
_with(base, o) := object.union(object.remove(base, object.keys(o)), o)

_both := _body("both", ["customer", "provider"])

_status(r, id) := s if {
	some c in r.control_results
	c.id == id
	s := c.status
}

_cell_st(r, id, role) := s if {
	some c in r.control_results
	c.id == id
	s := c.roles[role]
}

# ── the index ────────────────────────────────────────────────────────────────

test_index_counts if {
	index.order == _ids
	count(index.labels) == 4
	count(index.themes) == 4
	{index.themes[id] | some id in index.order} == {"organizational", "technological"}
	count(index.CONTROL_INDEX) == 4
}

test_report_total_equals_index if {
	every inp in [good_customer, good_provider, good_both, {}] {
		r := _r(inp)
		r.total_controls == count(index.order)
		r.total_controls == 4
	}
}

# ── empty and missing input ──────────────────────────────────────────────────

test_empty_input_is_not_compliant if {
	r := _r({})
	r.compliant == false
	r.total_controls == 4
	r.passed_controls == 0
	r.failed_controls == 4
	r.not_applicable_controls == 0
	r.assessed_role == "both"
	r.roles_in_scope == ["customer", "provider"]
	_identity(r)
	count(r.violations) >= 8
}

test_input_of_other_type_is_not_compliant if {
	every bad in ["x", 1, null, true, [], {}] {
		r := _r(_inp(bad))
		r.compliant == false
		r.failed_controls == 4
	}
}

# ── all-pass, per role ───────────────────────────────────────────────────────

test_all_pass_customer if {
	r := _r(good_customer)
	r.compliant == true
	r.passed_controls == 4
	r.roles_in_scope == ["customer"]
	r.violation_count == 0
	r.base_isms_attested == true
	_identity(r)
}

test_all_pass_provider if {
	r := _r(good_provider)
	r.compliant == true
	r.passed_controls == 4
	r.roles_in_scope == ["provider"]
	_identity(r)
}

test_all_pass_both if {
	r := _r(good_both)
	r.compliant == true
	r.passed_controls == 4
	r.roles_in_scope == ["customer", "provider"]
	r.cell_result_counts.pass == 8
	_identity(r)
}

test_all_pass_both_with_one_role_not_applicable if {
	r := _r(good_both_with_not_applicable)
	r.compliant == true
	r.passed_controls == 4
	r.not_applicable_controls == 0
	r.cell_result_counts.not_applicable == 1
	_cell_st(r, "8.35", "provider") == "not_applicable"
	_identity(r)
}

# ── the role selector ────────────────────────────────────────────────────────

test_role_customer_needs_no_provider_results_and_ignores_them if {
	r := _r(_inp(_with(_body("customer", ["customer"]), {"controls": _all_true(["customer"])})))
	r.compliant == true
	r2 := _r(_inp(_with(_body("customer", ["customer", "provider"]), {"controls": {id: {"customer": true, "provider": false} | some id in _ids}})))
	r2.compliant == true
	r2.passed_controls == 4
	r2.results_outside_role == ["5.38.provider", "5.39.provider", "8.35.provider", "8.36.provider"]
}

test_role_provider_ignores_customer_results if {
	r := _r(_inp(_with(_body("provider", ["provider"]), {"controls": {id: {"customer": "x", "provider": true} | some id in _ids}})))
	r.compliant == true
	r.results_outside_role == ["5.38.customer", "5.39.customer", "8.35.customer", "8.36.customer"]
}

test_role_both_needs_both_roles if {
	r := _r(_inp(_with(_both, {"controls": _all_true(["customer"])})))
	r.compliant == false
	r.failed_controls == 4
	r.cell_result_counts.evidence_missing == 4
	r.cell_result_counts.pass == 4
}

test_role_missing_is_a_finding_and_both_roles_are_assessed if {
	r := _r(_inp(object.remove(_both, ["role"])))
	r.compliant == false
	r.assessed_role == "both"
	r.declared_role == null
	r.passed_controls == 4
	r.violation_count == 1
	_identity(r)
}

test_role_unknown_is_a_finding_and_both_roles_are_assessed if {
	every bad in ["Customer", "csp", "csc", "both ", "", null, true, 1, [], {}, "customer,provider"] {
		r := _r(_inp(_with(_both, {"role": bad})))
		r.compliant == false
		r.assessed_role == "both"
		r.passed_controls == 4
		r.violation_count == 1
	}
}

test_role_unknown_with_customer_only_results_fails_the_provider_cells if {
	r := _r(_inp(_with(_body("csp", ["customer"]), {"role": "csp"})))
	r.assessed_role == "both"
	r.compliant == false
	r.failed_controls == 4
}

# ── the link to the ISO/IEC 27001 ISMS ───────────────────────────────────────

test_isms_missing_is_a_finding if {
	r := _r(_inp(object.remove(_both, ["iso27001_isms_in_place"])))
	r.compliant == false
	r.base_isms_attested == false
	r.passed_controls == 4
	r.violation_count == 1
	_identity(r)
}

test_isms_false_null_and_strings_are_findings if {
	every bad in [false, null, "true", "false", "yes", 1, 0, [], {}] {
		r := _r(_inp(_with(_both, {"iso27001_isms_in_place": bad})))
		r.compliant == false
		r.base_isms_attested == false
		r.passed_controls == 4
		r.violation_count == 1
	}
}

# ── each control and role: false, strings, null, removed ─────────────────────

_set(role, id, r, v) := _inp(_with(_body(role, ["customer", "provider"]), {"controls": _with(_all_true(["customer", "provider"]), {id: _with(_cell(["customer", "provider"]), {r: v})})}))

_check_cell(role, id, r) if {
	f := _r(_set(role, id, r, false))
	f.compliant == false
	f.failed_controls == 1
	f.failed_control_ids == [id]
	_cell_st(f, id, r) == "fail"
	_status(f, id) == "fail"
	_identity(f)

	every bad in ["true", "false", "yes", "no", 1, 0, [], {}] {
		x := _r(_set(role, id, r, bad))
		x.compliant == false
		x.failed_controls == 1
		_cell_st(x, id, r) == "evidence_invalid"
		some m in x.violations
		contains(m, sprintf("ISO/IEC 27017 %v:", [id]))
		contains(m, "is not a boolean")
	}

	n := _r(_set(role, id, r, null))
	n.compliant == false
	_cell_st(n, id, r) == "evidence_missing"
	some m in n.violations
	contains(m, "is null")
}

test_every_cell_both_roles_slice_1 if {
	every id in ["5.38", "5.39"] {
		every r in ["customer", "provider"] { _check_cell("both", id, r) }
	}
}

test_every_cell_both_roles_slice_2 if {
	every id in ["8.35", "8.36"] {
		every r in ["customer", "provider"] { _check_cell("both", id, r) }
	}
}

test_every_cell_single_role if {
	every id in _ids {
		c := _r(_inp(_with(_body("customer", ["customer"]), {"controls": {i: {"customer": true} | some i in _ids; i != id}})))
		c.compliant == false
		c.failed_control_ids == [id]
		_cell_st(c, id, "customer") == "evidence_missing"
		p := _r(_inp(_with(_body("provider", ["provider"]), {"controls": {i: {"provider": i != id} | some i in _ids}})))
		p.compliant == false
		p.failed_control_ids == [id]
		_cell_st(p, id, "provider") == "fail"
	}
}

test_removing_a_control_or_a_role_entry_is_evidence_missing if {
	every id in _ids {
		r := _r(_inp(_with(_both, {"controls": object.remove(_all_true(["customer", "provider"]), [id])})))
		r.compliant == false
		r.failed_controls == 1
		_cell_st(r, id, "customer") == "evidence_missing"
		_cell_st(r, id, "provider") == "evidence_missing"
		r.violation_count == 2
		_identity(r)
	}
}

test_a_control_whose_result_is_not_an_object_is_a_finding if {
	every bad in [true, false, "true", null, 1, []] {
		r := _r(_inp(_with(_both, {"controls": _with(_all_true(["customer", "provider"]), {"5.38": bad})})))
		r.compliant == false
		r.failed_controls == 1
		_status(r, "5.38") == "fail"
		_cell_st(r, "5.38", "customer") == "evidence_missing"
		_cell_st(r, "5.38", "provider") == "evidence_missing"
	}
}

test_findings_name_the_field_the_role_and_the_control if {
	r := _r(_inp(_with(_both, {"controls": _with(_all_true(["customer", "provider"]), {"8.36": {"customer": true}})})))
	r.violations == {"ISO/IEC 27017 8.36: evidence missing: input.iso_27017.controls[\"8.36\"].provider not collected (provider role; Misuse of cloud services detected and prevented)"}
}

# ── not applicable ───────────────────────────────────────────────────────────

_na_inp(reason) := _inp(_with(_both, {
	"controls": _with(_all_true(["customer", "provider"]), {"8.36": {"customer": true}}),
	"not_applicable": {"8.36": {"provider": reason}},
}))

test_not_applicable_needs_a_reason if {
	every bad in ["", "   ", null, 1, true, [], {}] {
		r := _r(_na_inp(bad))
		r.compliant == false
		r.cell_result_counts.not_applicable == 0
		r.failed_controls == 1
		_cell_st(r, "8.36", "provider") == "evidence_invalid"
		_identity(r)
	}
}

test_not_applicable_beside_a_result_is_a_finding if {
	inp := _inp(object.union(_both, {"not_applicable": {"5.38": {"customer": "nothing to do"}}}))
	r := _r(inp)
	r.compliant == false
	r.failed_controls == 1
	_cell_st(r, "5.38", "customer") == "evidence_invalid"
	some m in r.violations
	contains(m, "not both")
}

test_a_control_not_applicable_for_every_role_in_scope_is_not_applicable if {
	inp := _inp({
		"role": "both",
		"iso27001_isms_in_place": true,
		"controls": {"5.38": {"customer": true, "provider": true}, "5.39": {"customer": true, "provider": true}, "8.35": {"customer": true, "provider": true}},
		"not_applicable": {"8.36": {"customer": "no cloud services are used", "provider": "no cloud services are provided"}},
	})
	r := _r(inp)
	r.compliant == true
	r.passed_controls == 3
	r.not_applicable_controls == 1
	r.not_applicable_ids == ["8.36"]
	_status(r, "8.36") == "not_applicable"
	_identity(r)
}

test_all_not_applicable_is_not_compliant if {
	na := {id: {"customer": "x", "provider": "y"} | some id in _ids}
	r := _r(_inp({"role": "both", "iso27001_isms_in_place": true, "not_applicable": na}))
	r.compliant == false
	r.not_applicable_controls == 4
	r.passed_controls == 0
	r.violation_count == 0
	_identity(r)
}

test_absence_is_never_not_applicable if {
	r := _r(_inp(_with(_both, {"controls": {}})))
	r.not_applicable_controls == 0
	r.failed_controls == 4
}

test_not_applicable_outside_the_declared_role_is_ignored_and_listed if {
	inp := _inp(_with(_body("customer", ["customer"]), {"not_applicable": {"8.35": {"provider": "n/a"}}}))
	r := _r(inp)
	r.compliant == true
	r.results_outside_role == ["8.35.provider"]
}

# ── unknown ids, roles and containers ────────────────────────────────────────

test_unknown_ids_are_reported if {
	inp := _inp(_with(_both, {
		"controls": _with(_all_true(["customer", "provider"]), {"CLD.6.3.1": {"customer": true}, "8.37": {"customer": true}, "5.40": {"customer": true}}),
		"not_applicable": {"CLD.8.1.5": {"customer": "none"}},
	}))
	r := _r(inp)
	r.compliant == false
	r.violation_count == 4
	r.passed_controls == 4
	some m in r.violations
	contains(m, "\"CLD.8.1.5\"] is not a control id")
}

test_unknown_role_keys_are_reported if {
	inp := _inp(_with(_both, {"controls": _with(_all_true(["customer", "provider"]), {"5.38": {"customer": true, "provider": true, "partner": true}})}))
	r := _r(inp)
	r.compliant == false
	r.violation_count == 1
	r.passed_controls == 4
	some m in r.violations
	contains(m, "names the role \"partner\"")
}

test_containers_of_the_wrong_type_are_findings if {
	r := _r(_inp(_with(_both, {"controls": ["5.38"]})))
	r.compliant == false
	r.failed_controls == 4
	r2 := _r(_inp(_with(_both, {"not_applicable": "none"})))
	r2.compliant == false
	r2.passed_controls == 4
	r2.violation_count == 1
}

# ── arithmetic on a mixed input ──────────────────────────────────────────────

test_mixed_input_arithmetic if {
	inp := _inp({
		"role": "both",
		"iso27001_isms_in_place": true,
		"controls": {"5.38": {"customer": true, "provider": true}, "5.39": {"customer": false, "provider": true}, "8.35": {"customer": "true"}},
		"not_applicable": {"8.36": {"customer": "n/a", "provider": ""}},
	})
	r := _r(inp)
	r.total_controls == 4
	r.passed_controls == 1
	r.failed_controls == 3
	r.not_applicable_controls == 0
	r.cell_result_counts == {"pass": 3, "fail": 1, "evidence_missing": 1, "evidence_invalid": 2, "not_applicable": 1}
	_identity(r)
	count(r.control_results) == 4
}
