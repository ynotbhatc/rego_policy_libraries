package cis.windows_11_test

import rego.v1

# Validation fix pass 2026-10-17.

test_absent_domain_joined_does_not_pass_8_1_7 if {
	v := data.cis.windows_11.violations with input as {"system": {}}
	some m in v
	startswith(m, "8.1.7:")
}

test_not_domain_joined_passes_8_1_7 if {
	v := data.cis.windows_11.violations with input as {"system": {"is_domain_joined": false}}
	not any_with_prefix(v, "8.1.7:")
}

test_domain_joined_requires_setting if {
	v := data.cis.windows_11.violations with input as {"system": {"is_domain_joined": true}}
	any_with_prefix(v, "8.1.7:")
}

test_absent_domain_controller_does_not_pass_5_28 if {
	v := data.cis.windows_11.violations with input as {"system": {}}
	any_with_prefix(v, "5.28:")
}

test_non_dc_passes_5_28 if {
	v := data.cis.windows_11.violations with input as {"system": {"is_domain_controller": false}}
	not any_with_prefix(v, "5.28:")
}

any_with_prefix(v, prefix) if {
	some m in v
	startswith(m, prefix)
}
