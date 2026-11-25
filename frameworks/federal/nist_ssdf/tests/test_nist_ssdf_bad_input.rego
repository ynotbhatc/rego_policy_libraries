# Bad input never passes (issue #301, audit 2026-11-24): data-driven over the all-pass fixture of
# test_nist_ssdf.rego. Every yes/no fact is replaced by the strings "true", "false" and "no", by null, 0
# and 1, and removed, one at a time; the report must not be compliant, the score must drop below 100, and
# the counts must still add up.
package nist_ssdf.bad_input_test

import rego.v1

import data.nist_ssdf.main
import data.nist_ssdf.main_test.compliant_input as ok

_bool_paths := {path |
	walk(ok, [path, value])
	is_boolean(value)
}

# Documented in the PS input contract, not deciding a check by their value (see ps_protect_software.rego).
_supporting := {
	["source_control", "change_tracking"],
	["provenance", "artifacts_signed"],
	["release_management", "provenance_recorded"],
}

_replaced(path, value) := json.patch(ok, [{"op": "replace", "path": path, "value": value}])

_rejected(inp) if {
	report := main.compliance_report with input as inp
	report.compliant == false
	report.overall_compliance == "FAIL"
	report.compliance_percentage < 100
	report.failing_controls == 1
	report.passing_controls + report.failing_controls == report.total_controls
	report.total_controls == 42
}

test_fixture_passes if {
	report := main.compliance_report with input as ok
	report.compliant == true
	report.compliance_percentage == 100
	count(_bool_paths) == 47
}

test_empty_input_fails_every_control if {
	report := main.compliance_report with input as {}
	report.compliant == false
	report.failing_controls == 42
	report.passing_controls == 0
	report.compliance_percentage == 0
}

test_mistyped_fact_never_passes if {
	every path in _bool_paths {
		every value in ["true", "false", "no", null, 0, 1] {
			_rejected(_replaced(path, value))
		}
	}
}

test_removed_fact_fails_unless_supporting if {
	passing := {path |
		some path in _bool_paths
		main.compliant with input as json.patch(ok, [{"op": "remove", "path": path}])
	}
	passing == _supporting
}

test_false_supporting_fact_does_not_decide if {
	every path in _supporting {
		main.compliant with input as _replaced(path, false)
	}
}

test_mistyped_supporting_fact_names_the_problem if {
	vs := main.all_violations with input as _replaced(["provenance", "artifacts_signed"], "true")
	vs == ["PS.2.1: Release integrity verification cannot be attested — evidence invalid: input.provenance.artifacts_signed is not a boolean (got string)"]
}

# One finding per check: a mistyped supporting fact replaces the check's finding, it does not add a second.
test_mistyped_supporting_fact_does_not_double_count if {
	inp := {"source_control": {"change_tracking": "true"}, "provenance": {"artifacts_signed": null}, "release_management": {"provenance_recorded": 1}}
	report := main.compliance_report with input as inp
	report.failing_controls == 42
	report.passing_controls == 0
}
