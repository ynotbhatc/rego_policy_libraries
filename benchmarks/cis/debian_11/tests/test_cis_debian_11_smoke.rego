package cis_debian_11_test

import rego.v1

import data.cis_debian_11

# Phase 1 contract smoke test.
# Proves a well-formed report object is returned on empty input, never the
# `undefined -> {}` collapse.
# Entrypoint: data.cis_debian_11.compliance_summary
# (The primary top-level report data.cis_debian_11.compliance_assessment is
#  undefined on empty input — it dereferences input.system_info and requires
#  real input by design; see broken-endpoint notes.)
test_report_wellformed_on_empty_input if {
	report := cis_debian_11.compliance_summary with input as {}
	is_object(report)
	count(report) > 0
}
