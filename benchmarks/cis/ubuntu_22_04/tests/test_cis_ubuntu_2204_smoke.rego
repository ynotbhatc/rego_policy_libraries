package cis_ubuntu_22_04_test

import rego.v1

import data.cis_ubuntu_22_04

# Phase 1 contract smoke test.
# Proves a well-formed report object is returned on empty input, never the
# `undefined -> {}` collapse.
#
# This now tests the PRIMARY endpoint, compliance_assessment — the one the
# assessment playbook actually queries. It used to test compliance_summary
# instead, with a comment explaining that the primary endpoint collapses on
# empty input "by design". That was testing around the defect rather than
# pinning it: any caller whose facts lacked system_info got {} stored as its
# assessment while the job stayed green.
test_report_wellformed_on_empty_input if {
	report := cis_ubuntu_22_04.compliance_assessment with input as {}
	is_object(report)
	count(report) > 0
	report.system_info.distribution == "unknown"
}

test_summary_wellformed_on_empty_input if {
	report := cis_ubuntu_22_04.compliance_summary with input as {}
	is_object(report)
	count(report) > 0
}
