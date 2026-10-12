package nist.csf.protect_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/cybersecurity_framework_2.0/protect/access_control.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_access_control_loads_on_empty_input if {
	m := data.nist.csf.protect with input as {}
	is_object(m)
}
