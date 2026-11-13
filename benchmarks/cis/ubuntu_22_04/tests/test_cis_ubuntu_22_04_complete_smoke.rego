package cis_ubuntu_22_04_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_22_04/cis_ubuntu_22_04_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_ubuntu_22_04_complete_loads_on_empty_input if {
	m := data.cis_ubuntu_22_04 with input as {}
	is_object(m)
}

test_cis_ubuntu_22_04_complete_violations_on_empty_input if {
	v := data.cis_ubuntu_22_04.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: the Level 2 profile must reach the roll-up (import path was wrong).
test_level2_profile_adds_l2_violations if {
	v := data.cis_ubuntu_22_04.violations with input as {"profile": "level2"}
	some x in v
	startswith(x, "CIS L2")
}

test_level2_profile_blocks_compliant if {
	not data.cis_ubuntu_22_04.compliant with input as {"profile": "level2"}
}

test_level1_profile_has_no_l2_violations if {
	v := data.cis_ubuntu_22_04.violations with input as {"profile": "level1"}
	every x in v {
		not startswith(x, "CIS L2")
	}
}
