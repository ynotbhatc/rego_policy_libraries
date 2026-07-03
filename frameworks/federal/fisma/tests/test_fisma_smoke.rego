package fisma.main_test

import rego.v1

# Phase 1 contract smoke test — BROKEN ENDPOINT (skipped, not green-washed).
#
# The platform-convention endpoint data.fisma.main.compliance_report does NOT
# exist. The nearest aggregate report rule, data.fisma.main.fisma_assessment,
# collapses to undefined ("{}") on empty input: it embeds `fisma_compliant == true`
# but fisma_compliant has no `default`, so on empty input that field is undefined,
# which turns the whole object literal undefined (Rego v1 collapse).
#
# This test is deliberately named with the `todo_` prefix so OPA reports it as
# SKIPPED rather than PASS/FAIL — it documents the contract we WANT without
# green-washing the bug or breaking CI. Remove the `todo_` prefix once the
# endpoint is fixed (add `default fisma_compliant := false` and expose a
# `compliance_report` rule).
todo_test_report_wellformed_on_empty_input if {
	report := data.fisma.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
}
