package cis_rhel9.ssh_validation_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

ids(v) := {x.control_id | some x in v; x.control_id}

test_ssh_unset_ciphers_flagged if {
	v := data.cis_rhel9.ssh_validation.violations with input as {"ssh": {"config": {}}}
	"5.1.13" in ids(v)
}

test_ssh_unset_macs_flagged if {
	v := data.cis_rhel9.ssh_validation.violations with input as {"ssh": {"config": {}}}
	"5.1.14" in ids(v)
}

test_ssh_unset_kex_flagged if {
	v := data.cis_rhel9.ssh_validation.violations with input as {"ssh": {"config": {}}}
	"5.1.15" in ids(v)
}

test_ssh_strong_list_ok if {
	i := {"ssh": {"config": {
		"Ciphers": ["aes256-gcm@openssh.com", "aes128-ctr"],
		"MACs": ["hmac-sha2-512"],
		"KexAlgorithms": ["curve25519-sha256"],
	}}}
	v := data.cis_rhel9.ssh_validation.violations with input as i
	not "5.1.13" in ids(v)
	not "5.1.14" in ids(v)
	not "5.1.15" in ids(v)
}

test_ssh_strong_csv_ok if {
	i := {"ssh": {"config": {"Ciphers": "aes256-gcm@openssh.com,aes128-ctr"}}}
	v := data.cis_rhel9.ssh_validation.violations with input as i
	not "5.1.13" in ids(v)
}

test_ssh_weak_cipher_in_csv_flagged if {
	i := {"ssh": {"config": {"Ciphers": "aes256-gcm@openssh.com, aes128-cbc"}}}
	v := data.cis_rhel9.ssh_validation.violations with input as i
	"5.1.13" in ids(v)
}

test_ssh_weak_mac_list_flagged if {
	i := {"ssh": {"config": {"MACs": ["hmac-sha1"]}}}
	v := data.cis_rhel9.ssh_validation.violations with input as i
	"5.1.14" in ids(v)
}
