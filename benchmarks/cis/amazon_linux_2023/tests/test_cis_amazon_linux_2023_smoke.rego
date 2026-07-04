package cis_amazon_linux_2023_test

import rego.v1

import data.cis_amazon_linux_2023

# Phase 1 contract smoke test.
# Proves the live orchestrator endpoint returns a well-formed report object on
# empty input, never the `undefined -> {}` collapse.
# Entrypoint: data.cis_amazon_linux_2023.executive_summary
# (defined in cis_al20239_complete.rego, the _complete orchestrator).
test_report_wellformed_on_empty_input if {
	report := cis_amazon_linux_2023.executive_summary with input as {}
	is_object(report)
	count(report) > 0
}
