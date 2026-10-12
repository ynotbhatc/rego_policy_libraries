package cis.mobile.android_test

import rego.v1

# Generated smoke test for benchmarks/cis/mobile_devices/android/android_security.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_android_security_loads_on_empty_input if {
	m := data.cis.mobile.android with input as {}
	is_object(m)
}
