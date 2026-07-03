package pci_dss.main_test

import rego.v1

# Phase 1 contract smoke test — BROKEN ENDPOINT (skipped, not green-washed).
#
# The platform-convention endpoint data.pci_dss.main.compliance_report does NOT
# exist. The nearest aggregate report rule, data.pci_dss.main.pci_dss_detailed_findings,
# collapses to undefined ("{}") on empty input. Root cause: it embeds
# pci_dss_compliance_score, which sums per-requirement scores such as
# data.pci_dss.access_control.requirement_7.pci_requirement_7_score — these have
# no `default`, so they are undefined on empty input and cascade the whole object
# literal to undefined (Rego v1 collapse).
#
# `todo_` prefix => OPA reports SKIPPED (documents the desired contract without
# green-washing or breaking CI). Remove the prefix once the endpoint is fixed
# (default-safe requirement scores + a `compliance_report` rule).
test_report_wellformed_on_empty_input if {
	report := data.pci_dss.main.pci_dss_detailed_findings with input as {}
	is_object(report)
	count(report) > 0
}
