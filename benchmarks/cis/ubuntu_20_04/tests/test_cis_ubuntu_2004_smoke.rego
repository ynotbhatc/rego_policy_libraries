package cis_ubuntu_20_04_test

import rego.v1

import data.cis_ubuntu_20_04

# Phase 1 contract smoke test.
# Proves a well-formed report object is returned on empty input, never the
# `undefined -> {}` collapse.
# Entrypoint: data.cis_ubuntu_20_04.compliance_summary
# (The primary top-level report data.cis_ubuntu_20_04.compliance_assessment is
#  undefined on empty input — it dereferences input.system_info and requires
#  real input by design; see broken-endpoint notes.)
test_report_wellformed_on_empty_input if {
	report := cis_ubuntu_20_04.compliance_summary with input as {}
	is_object(report)
	count(report) > 0
}
