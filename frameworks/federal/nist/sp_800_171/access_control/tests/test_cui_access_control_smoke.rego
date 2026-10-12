package nist.sp800_171.access_control_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/sp_800_171/access_control/cui_access_control.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cui_access_control_loads_on_empty_input if {
	m := data.nist.sp800_171.access_control with input as {}
	is_object(m)
}
