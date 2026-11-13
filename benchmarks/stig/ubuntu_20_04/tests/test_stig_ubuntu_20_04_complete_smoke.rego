package stig.ubuntu_20_04_test

import rego.v1

# Generated smoke test for benchmarks/stig/ubuntu_20_04/stig_ubuntu_20_04_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_stig_ubuntu_20_04_complete_loads_on_empty_input if {
	m := data.stig.ubuntu_20_04 with input as {}
	is_object(m)
}

# Semantic review 2026-11-13: missing evidence is Open, not Not_a_Finding.
test_guest_password_findings_open_without_evidence if {
	data.stig.ubuntu_20_04.guest_account_status == "Open" with input as {"x": 1}
	data.stig.ubuntu_20_04.password_history_status == "Open" with input as {"x": 1}
	data.stig.ubuntu_20_04.password_length_status == "Open" with input as {"x": 1}
}

test_guest_password_findings_pass_with_evidence if {
	inp := {"local_accounts": {"guest": {"enabled": false}}, "password_policy": {"password_history_size": 24, "minimum_password_length": 14}}
	data.stig.ubuntu_20_04.guest_account_status == "Not_a_Finding" with input as inp
	data.stig.ubuntu_20_04.password_history_status == "Not_a_Finding" with input as inp
	data.stig.ubuntu_20_04.password_length_status == "Not_a_Finding" with input as inp
}

test_guest_enabled_and_short_policy_open if {
	inp := {"local_accounts": {"guest": {"enabled": true}}, "password_policy": {"password_history_size": 5, "minimum_password_length": 8}}
	data.stig.ubuntu_20_04.guest_account_status == "Open" with input as inp
	data.stig.ubuntu_20_04.password_length_status == "Open" with input as inp
}
