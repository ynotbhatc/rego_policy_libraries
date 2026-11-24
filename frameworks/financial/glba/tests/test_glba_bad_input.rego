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
