package nerc_cip.cip_003_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/nerc_cip/cip_003_security_management.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cip_003_security_management_loads_on_empty_input if {
	m := data.nerc_cip.cip_003 with input as {}
	is_object(m)
}

test_cip_003_security_management_violations_on_empty_input if {
	v := data.nerc_cip.cip_003.violations with input as {}
	count(v) > 0
}
