package cis_rocky_linux_8.filesystem_test

import rego.v1

# Generated smoke test for benchmarks/cis/rocky_linux_8/filesystem_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_filesystem_validation_loads_on_empty_input if {
	m := data.cis_rocky_linux_8.filesystem with input as {}
	is_object(m)
}

test_filesystem_validation_violations_on_empty_input if {
	v := data.cis_rocky_linux_8.filesystem.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: a missing disabled_filesystem_modules fact must not pass.
test_missing_disabled_filesystem_modules_flagged if {
	v := data.cis_rocky_linux_8.filesystem.filesystem_module_violations with input as {}
	"CIS 1.1.1.x: evidence missing - disabled_filesystem_modules not collected" in v
}

test_disabled_filesystem_modules_present_not_flagged if {
	v := data.cis_rocky_linux_8.filesystem.filesystem_module_violations with input as {"disabled_filesystem_modules": {"cramfs": true, "squashfs": true, "udf": true}}
	count(v) == 0
}
