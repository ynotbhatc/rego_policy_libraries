package cis_windows_server_2016_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2016/cis_windows_server_2016.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_windows_server_2016_loads_on_empty_input if {
	m := data.cis_windows_server_2016 with input as {}
	is_object(m)
}

test_cis_windows_server_2016_violations_on_empty_input if {
	v := data.cis_windows_server_2016.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13 regressions.
_ids(v) := {split(m, ":")[0] | some m in v}

test_single_fact_supplied_is_not_compliant if {
	inp := {"restricted_groups": {"administrators": ["Administrator"]}}
	not data.cis_windows_server_2016.compliant with input as inp
	ids := _ids(data.cis_windows_server_2016.violations) with input as inp
	every id in ["1.1.1", "1.2.1", "1.3.1", "2.2.1", "2.2.3", "3.1.1", "5.1", "6.1", "7.1", "8.1.1", "8.9.1"] {
		id in ids
	}
}

test_missing_numeric_fact_violates if {
	v := data.cis_windows_server_2016.password_policy_violations with input as {}
	count(v) == 1
}

test_numeric_fact_compliant_passes if {
	v := data.cis_windows_server_2016.password_policy_violations with input as {"password_policy": {"enforce_password_history": "24"}}
	count(v) == 0
}

test_security_options_violation_counted_once if {
	inp := {"security_options": {"accounts_administrator_account_status": "Enabled"}}
	v := data.cis_windows_server_2016.violations with input as inp
	count([m | some m in v; startswith(m, "7.1:")]) == 1
}
