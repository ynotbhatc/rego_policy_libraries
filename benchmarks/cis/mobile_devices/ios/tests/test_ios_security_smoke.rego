package cis.mobile.ios_test

import rego.v1

# Generated smoke test for benchmarks/cis/mobile_devices/ios/ios_security.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ios_security_loads_on_empty_input if {
	m := data.cis.mobile.ios with input as {}
	is_object(m)
}
