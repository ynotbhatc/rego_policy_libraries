package cis_windows_server_2019_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2019_modular/cis_windows_server_2019_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

# Evaluating the whole data.cis_windows_server_2019 document took ~5 s on CI and hit OPA's
# default test timeout; the report itself is covered by test_main / test_compliance_assessment.
test_cis_windows_server_2019_complete_loads_on_empty_input if {
	ids := data.cis_windows_server_2019.evaluated_control_ids with input as {}
	count(ids) > 0
}
