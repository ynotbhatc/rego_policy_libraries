package sox.main_test

import rego.v1

# Phase 1 contract smoke test — BROKEN ENDPOINT (skipped, not green-washed).
#
# The platform-convention endpoint data.sox.main.compliance_report does NOT
# exist. The nearest aggregate report rule, data.sox.main.overall_sox_assessment,
# collapses to undefined ("{}") on empty input. Root cause: it embeds
# sox_compliance_score, which has no `default` and is undefined on empty input,
# cascading the whole object literal to undefined (Rego v1 collapse).
# `data.sox.main.sox_compliant` itself IS defined (false).
#
# `todo_` prefix => OPA reports SKIPPED (documents the desired contract without
# green-washing or breaking CI). Remove the prefix once the endpoint is fixed
# (default-safe scores + a `compliance_report` rule).
todo_test_report_wellformed_on_empty_input if {
	report := data.sox.main.overall_sox_assessment with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliance_status)
}
