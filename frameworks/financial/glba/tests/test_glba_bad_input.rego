# Bad input never passes (issue #301, audit 2026-11-24): data-driven over the all-pass fixture of
# test_glba_main.rego. Every yes/no fact is replaced by the strings "true" and "false", by null, 0 and 1,
# and removed, one at a time; the report must not be compliant and a finding must name the field and the
# evidence problem.
package glba.bad_input_test

import rego.v1

import data.glba.main
import data.glba.main_test.compliant_input as ok

_bool_paths := {path |
	walk(ok, [path, value])
	is_boolean(value)
}

_dotted(path) := concat(".", [sprintf("%v", [p]) | some p in path])

_replaced(path, value) := json.patch(ok, [{"op": "replace", "path": path, "value": value}])

_removed(path) := json.patch(ok, [{"op": "remove", "path": path}])

# Not compliant, and some finding names the field with the given evidence problem.
_rejected(inp, path, problem) if {
	report := main.compliance_report with input as inp
	report.compliant == false
	report.violation_count > 0
	report.violation_count <= report.total_controls
	report.failed_controls == report.violation_count
	some v in report.violations
	contains(v, sprintf("%s: input.%s ", [problem, _dotted(path)]))
}

test_fixture_passes if {
	report := main.compliance_report with input as ok
	report.compliant == true
	report.violation_count == 0
	report.failed_controls == 0
	count(_bool_paths) == 33
}

test_empty_input_fails if {
	report := main.compliance_report with input as {}
	report.compliant == false
	report.violation_count > 0
	every v in report.violations {
		contains(v, "evidence missing: ")
	}
}

test_string_true_never_passes if {
	every path in _bool_paths {
		_rejected(_replaced(path, "true"), path, "evidence invalid")
	}
}

test_string_false_never_passes if {
	every path in _bool_paths {
		_rejected(_replaced(path, "false"), path, "evidence invalid")
	}
}

test_string_no_never_passes if {
	every path in _bool_paths {
		_rejected(_replaced(path, "no"), path, "evidence invalid")
	}
}

test_null_never_passes if {
	every path in _bool_paths {
		_rejected(_replaced(path, null), path, "evidence invalid")
	}
}

test_one_and_zero_never_pass if {
	every path in _bool_paths {
		every n in [0, 1] {
			_rejected(_replaced(path, n), path, "evidence invalid")
		}
	}
}

test_removed_fact_never_passes if {
	every path in _bool_paths {
		_rejected(_removed(path), path, "evidence missing")
	}
}

test_mistyped_finding_wording if {
	some path in _bool_paths
	report := main.compliance_report with input as _replaced(path, "true")
	some v in report.violations
	endswith(v, sprintf("[evidence invalid: input.%s is not a boolean (got string)]", [_dotted(path)]))
}

# A plain false keeps the finding text it always had: no evidence note.
test_boolean_false_has_no_evidence_note if {
	every path in {p | some p in _bool_paths; object.get(ok, p, null) == true} {
		report := main.compliance_report with input as _replaced(path, false)
		report.compliant == false
		every v in report.violations {
			not contains(v, "evidence invalid")
		}
	}
}

# ── Alternatives: one true alternative satisfies the control, a mistyped one fails it ───────────────────────
test_mistyped_alternative_fails_even_when_primary_is_true if {
	cases := [
		{"encryption": {"customer_info": {"in_transit": true, "at_rest": true}, "compensating_controls_approved": "false"}},
		{"mfa": {"all_information_systems": true, "equivalent_approved_in_writing": "true"}},
		{"disposal": {"within_two_years": true, "retention_policy_reviewed": true, "retention_justified": null}},
		{"testing": {"continuous_monitoring": true, "penetration_test": {"annual": "true"}}},
		{"testing": {"continuous_monitoring": true, "vulnerability_assessment": {"semi_annual": 1}}},
	]
	every c in cases {
		report := main.compliance_report with input as object.union(ok, c)
		report.compliant == false
		some v in report.violations
		contains(v, "evidence invalid")
	}
}

test_string_alternative_does_not_satisfy if {
	inp := object.union(ok, {"mfa": {"all_information_systems": false, "equivalent_approved_in_writing": "true"}})
	report := main.compliance_report with input as inp
	report.compliant == false
}

# The small-institution exemption is the boolean true, stated in the input; a string is not an exemption.
test_string_exemption_is_not_an_exemption if {
	stripped := json.remove(ok, ["risk_assessment", "incident_response", "board_report", "testing"])
	report := main.compliance_report with input as object.union(stripped, {"small_institution_exemption": "true"})
	report.compliant == false
	report.small_institution_exemption == false
}

# The kind of institution is stated (applicability, 16 CFR 314.1(b)).
test_entity_type_must_be_stated if {
	every inp in [json.remove(ok, ["entity_type"]), object.union(ok, {"entity_type": null}), object.union(ok, {"entity_type": ""}), object.union(ok, {"entity_type": true})] {
		report := main.compliance_report with input as inp
		report.compliant == false
		some v in report.violations
		startswith(v, "GLBA input contract (16 CFR 314.1(b))")
	}
}

# Audit 2026-11-24 round 2: the declared total agrees with the rule set. 34 checks of 16 CFR 314.4(a)-(j),
# one finding each (it said 33 while 34 rules reported). The 314.1(b) applicability finding is an
# input-contract finding: in violation_count, not in failed_controls.
_counts_add_up(report) if {
	report.total_controls == 34
	report.failed_controls <= report.total_controls
	report.passed_controls >= 0
	(report.passed_controls + report.failed_controls) + report.not_applicable_controls == report.total_controls
	report.violation_count == report.failed_controls + report.input_contract_findings
}

test_declared_total_matches_rule_set_on_empty_input if {
	report := main.compliance_report with input as {}
	report.failed_controls == 34
	report.passed_controls == 0
	report.not_applicable_controls == 0
	report.input_contract_findings == 1
	report.violation_count == 35
	_counts_add_up(report)
}

test_one_finding_per_paragraph_group_on_empty_input if {
	report := main.compliance_report with input as {}
	expected := {
		"16 CFR 314.4(a)": 1, "16 CFR 314.4(b)": 3, "16 CFR 314.4(c)(1)": 3, "16 CFR 314.4(c)(2)": 2,
		"16 CFR 314.4(c)(3)": 2, "16 CFR 314.4(c)(4)": 2, "16 CFR 314.4(c)(5)": 1, "16 CFR 314.4(c)(6)": 2,
		"16 CFR 314.4(c)(7)": 1, "16 CFR 314.4(c)(8)": 2, "16 CFR 314.4(d)": 2, "16 CFR 314.4(e)": 3,
		"16 CFR 314.4(f)": 3, "16 CFR 314.4(g)": 1, "16 CFR 314.4(h)": 3, "16 CFR 314.4(i)": 2,
		"16 CFR 314.5": 1,
	}
	every prefix, n in expected {
		count([v | some v in report.violations; startswith(v, prefix)]) == n
	}
	sum([n | some _, n in expected]) == 34
}

test_counts_add_up_on_every_kind_of_input if {
	inputs := [
		{}, ok, {"small_institution_exemption": true},
		object.union(ok, {"small_institution_exemption": true}),
		json.patch(ok, [{"op": "remove", "path": "/entity_type"}]),
		{"entity_type": "auto dealer"},
		{"entity_type": "auto dealer", "small_institution_exemption": true},
	]
	every inp in inputs {
		report := main.compliance_report with input as inp
		_counts_add_up(report)
	}
}

test_exemption_counts_not_applicable if {
	report := main.compliance_report with input as {"entity_type": "tax preparer", "small_institution_exemption": true}
	report.not_applicable_controls == 10
	report.failed_controls == 24
	report.passed_controls == 0
	report.input_contract_findings == 0
	passing := main.compliance_report with input as object.union(ok, {"small_institution_exemption": true})
	passing.compliant == true
	passing.passed_controls == 24
	passing.not_applicable_controls == 10
}

test_all_pass_counts if {
	report := main.compliance_report with input as ok
	report.passed_controls == 34
	report.failed_controls == 0
	report.not_applicable_controls == 0
}
