package stig.rhel_8.v2r9_rules_test

import rego.v1

# RHEL 8 V2R9 (2026-11-21): the three added rules, the changed checks (010020, 020200) and the banner pair
# (010040 ssh, 010060 /etc/issue), each pass / fail / evidence missing against the V2R9 check text.

fips_hashes := ["SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA3-256", "SHA3-384", "SHA3-512"]

# --- RHEL-08-010020: crypto policy FIPS, no subpolicies ---

test_010020_pass if {
	i := {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": fips_hashes, "min_rsa_size": 2048}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010020 == "Not_a_Finding" with input as i
}

test_010020_larger_rsa_size_pass if {
	i := {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": fips_hashes, "min_rsa_size": 3072}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010020 == "Not_a_Finding" with input as i
}

# a number sent as text is not read: evidence invalid, naming the fact and the type (owner ruling 2026-11-24)
test_010020_string_rsa_size_is_evidence_invalid if {
	every v in ["3072", " 3072 "] {
		f := data.stig.rhel_8.configuration_management.finding_rhel_08_010020 with input as {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": fips_hashes, "min_rsa_size": v}}
		f.status == "Open"
		f.detail == "RHEL-08-010020: evidence invalid — crypto_policy_state.min_rsa_size is not a number (got string)"
	}
	f := data.stig.rhel_8.configuration_management.finding_rhel_08_010020 with input as {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": fips_hashes, "min_rsa_size": 3072.5}}
	f.detail == "RHEL-08-010020: evidence invalid — crypto_policy_state.min_rsa_size is not a number (got a fraction)"
}

test_010020_subpolicy_open if {
	i := {"crypto_policy": "FIPS:OSPP", "crypto_policy_state": {"hash": fips_hashes, "min_rsa_size": 2048}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010020 == "Open" with input as i
}

test_010020_sha1_open if {
	i := {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": array.concat(fips_hashes, ["SHA1"]), "min_rsa_size": 2048}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010020 == "Open" with input as i
}

test_010020_short_hash_list_open if {
	i := {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": ["SHA2-256", "SHA2-384"], "min_rsa_size": 2048}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010020 == "Open" with input as i
}

test_010020_weak_rsa_and_type_trap_open if {
	every v in [1024, "2048 bits", null, true] {
		data.stig.rhel_8.configuration_management.status_rhel_08_010020 == "Open" with input as {"crypto_policy": "FIPS", "crypto_policy_state": {"hash": fips_hashes, "min_rsa_size": v}}
	}
}

test_010020_evidence_missing if {
	d := data.stig.rhel_8.configuration_management.detail_rhel_08_010020 with input as {"x": 1}
	contains(d, "evidence missing")
	startswith(d, "RHEL-08-010020: ")
}

# --- RHEL-08-010293: openssl.cnf includes opensslcnf.config ---

test_010293_pass if {
	i := {"openssl_cnf": {"lines": ["[ crypto_policy ]", ".include = /etc/crypto-policies/back-ends/opensslcnf.config"]}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010293 == "Not_a_Finding" with input as i
}

test_010293_commented_open if {
	i := {"openssl_cnf": {"lines": ["# .include = /etc/crypto-policies/back-ends/opensslcnf.config"]}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010293 == "Open" with input as i
}

test_010293_evidence_missing if {
	d := data.stig.rhel_8.configuration_management.detail_rhel_08_010293 with input as {"openssl_cnf": {"lines": "x"}}
	contains(d, "evidence missing")
}

# --- RHEL-08-010287: no uncommented CRYPTO_POLICY in /etc/sysconfig/sshd ---

test_010287_pass if {
	i := {"sshd_sysconfig": {"lines": ["# CRYPTO_POLICY=", "SSH_USE_STRONG_RNG=0"]}}
	data.stig.rhel_8.ssh_config.status_rhel_08_010287 == "Not_a_Finding" with input as i
}

test_010287_uncommented_open if {
	i := {"sshd_sysconfig": {"lines": ["CRYPTO_POLICY=-oCiphers=aes256-ctr"]}}
	data.stig.rhel_8.ssh_config.status_rhel_08_010287 == "Open" with input as i
}

test_010287_evidence_missing if {
	data.stig.rhel_8.ssh_config.status_rhel_08_010287 == "Open" with input as {"x": 1}
	d := data.stig.rhel_8.ssh_config.detail_rhel_08_010287 with input as {"x": 1}
	contains(d, "evidence missing")
}

# --- RHEL-08-030565: audit rule for useradd ---

test_030565_pass if {
	i := {"audit_rules": ["-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd"]}
	data.stig.rhel_8.audit_logging.status_rhel_08_030565 == "Not_a_Finding" with input as i
}

test_030565_commented_or_other_word_open if {
	every r in ["# -a always,exit -F path=/usr/sbin/useradd -F perm=x", "-a always,exit -F path=/usr/sbin/useraddx -F perm=x"] {
		data.stig.rhel_8.audit_logging.status_rhel_08_030565 == "Open" with input as {"audit_rules": [r]}
	}
}

test_030565_evidence_missing if {
	d := data.stig.rhel_8.audit_logging.detail_rhel_08_030565 with input as {"x": 1}
	contains(d, "evidence missing")
}

# --- RHEL-08-020200: 180-day maximum (V2R9) ---

test_020200_180_passes_181_open if {
	data.stig.rhel_8.account_auth.status_rhel_08_020200 == "Not_a_Finding" with input as {"password_policy": {"maxdays": 180}}
	data.stig.rhel_8.account_auth.status_rhel_08_020200 == "Open" with input as {"password_policy": {"maxdays": 181}}
	data.stig.rhel_8.account_auth.status_rhel_08_020200 == "Open" with input as {"password_policy": {"maxdays": -1}}
}

# --- banner pair ---

test_010060_issue_exact_banner if {
	b := data.stig.rhel_8.configuration_management.dod_banner
	i := {"login_banner": {"issue": replace(b, " -", "\n-")}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010060 == "Not_a_Finding" with input as i
	data.stig.rhel_8.configuration_management.status_rhel_08_010060 == "Not_a_Finding" with input as {"login_banner": {"issue": sprintf("%s\n", [b])}}
	data.stig.rhel_8.configuration_management.status_rhel_08_010060 == "Open" with input as {"login_banner": {"issue": "Authorized users only. U.S. Government system."}}
}

test_010040_ssh_banner if {
	b := data.stig.rhel_8.configuration_management.dod_banner
	data.stig.rhel_8.ssh_config.status_rhel_08_010040 == "Not_a_Finding" with input as {"ssh_config": {"Banner": "/etc/issue", "banner_text": b}}
	data.stig.rhel_8.ssh_config.status_rhel_08_010040 == "Open" with input as {"ssh_config": {"Banner": "none", "banner_text": b}}
	data.stig.rhel_8.ssh_config.status_rhel_08_010040 == "Open" with input as {"ssh_config": {"Banner": "/etc/issue", "banner_text": "Authorized users only"}}
	d := data.stig.rhel_8.ssh_config.detail_rhel_08_010040 with input as {"ssh_config": {"Banner": "/etc/issue"}}
	contains(d, "evidence missing")
}
