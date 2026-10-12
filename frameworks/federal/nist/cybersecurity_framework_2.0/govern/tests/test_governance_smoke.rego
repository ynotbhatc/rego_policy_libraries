package nist.csf.govern_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/cybersecurity_framework_2.0/govern/governance.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_governance_loads_on_empty_input if {
	m := data.nist.csf.govern with input as {}
	is_object(m)
}
