package cis_windows_server_2022_legacy_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2022/cis_windows_server_2022.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_windows_server_2022_loads_on_empty_input if {
	m := data.cis_windows_server_2022_legacy with input as {}
	is_object(m)
}

test_cis_windows_server_2022_violations_on_empty_input if {
	v := data.cis_windows_server_2022_legacy.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13 regressions.
_ids(v) := {split(m, ":")[0] | some m in v}

test_single_fact_supplied_is_not_compliant if {
	inp := {"restricted_groups": {"administrators": ["Administrator"]}}
	not data.cis_windows_server_2022_legacy.compliant with input as inp
	ids := _ids(data.cis_windows_server_2022_legacy.violations) with input as inp
	every id in ["1.1.1", "1.2.1", "1.3.1", "2.2.1", "2.2.3", "2.3.1", "3.1.1", "5.1", "6.1", "7.1", "8.1.1", "8.9.1", "9.1.1"] {
		id in ids
	}
}

test_missing_defender_asr_fact_violates if {
	v := data.cis_windows_server_2022_legacy.windows_defender_violations with input as {}
	count(v) == 1
}

test_defender_asr_enabled_passes if {
	v := data.cis_windows_server_2022_legacy.windows_defender_violations with input as {"windows_defender": {"configure_attack_surface_reduction_rules": "Enabled"}}
	count(v) == 0
}

test_numeric_fact_compliant_passes if {
	v := data.cis_windows_server_2022_legacy.password_policy_violations with input as {"password_policy": {"enforce_password_history": 24}}
	count(v) == 0
}
