package corporate.backup_test

import rego.v1

# Generated smoke test for frameworks/management/corporate/backup_policy.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_backup_policy_loads_on_empty_input if {
	m := data.corporate.backup with input as {}
	is_object(m)
}
