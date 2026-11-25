# Bad input never passes (issue #301, audit 2026-11-24): data-driven over the all-pass fixture of
# test_cobit_main.rego. Every yes/no fact is replaced by the strings "true" and "false", by null, 0 and 1,
# and removed, one at a time; the report must not be compliant and a finding must name the field and the
# evidence problem.
package cobit.bad_input_test

import rego.v1

import data.cobit.main
import data.cobit.main_test.compliant_input as ok

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
	count(_bool_paths) == 18
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
