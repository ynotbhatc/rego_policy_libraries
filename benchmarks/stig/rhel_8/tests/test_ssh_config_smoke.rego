package stig.rhel_8.ssh_config_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_8/ssh_config.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ssh_config_loads_on_empty_input if {
	m := data.stig.rhel_8.ssh_config with input as {}
	is_object(m)
}

test_ssh_config_report_wellformed_on_empty_input if {
	report := data.stig.rhel_8.ssh_config.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ssh_config_fail_closed_on_empty_input if {
	report := data.stig.rhel_8.ssh_config.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_ssh_config_violations_on_empty_input if {
	v := data.stig.rhel_8.ssh_config.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: missing evidence must not pass.

test_ciphers_unapproved_chacha_open if {
	data.stig.rhel_8.ssh_config.status_rhel_08_010291 == "Open" with input as {"ssh_config": {"Ciphers": "chacha20-poly1305@openssh.com"}}
}

test_ciphers_cbc_open if {
	data.stig.rhel_8.ssh_config.status_rhel_08_010291 == "Open" with input as {"ssh_config": {"Ciphers": "aes128-cbc,aes256-cbc"}}
}

test_ciphers_ctr_pass if {
	data.stig.rhel_8.ssh_config.status_rhel_08_010291 == "Not_a_Finding" with input as {"ssh_config": {"Ciphers": "aes256-ctr,aes192-ctr,aes128-ctr"}}
}

test_macs_unapproved_open if {
	data.stig.rhel_8.ssh_config.status_rhel_08_010290 == "Open" with input as {"ssh_config": {"MACs": "umac-64@openssh.com,hmac-sha2-256"}}
}

test_macs_sha2_pass if {
	data.stig.rhel_8.ssh_config.status_rhel_08_010290 == "Not_a_Finding" with input as {"ssh_config": {"MACs": "hmac-sha2-512,hmac-sha2-256"}}
}
