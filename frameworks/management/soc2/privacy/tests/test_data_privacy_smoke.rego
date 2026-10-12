package soc2.privacy.data_privacy_test

import rego.v1

# Generated smoke test for frameworks/management/soc2/privacy/data_privacy.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_data_privacy_loads_on_empty_input if {
	m := data.soc2.privacy.data_privacy with input as {}
	is_object(m)
}
