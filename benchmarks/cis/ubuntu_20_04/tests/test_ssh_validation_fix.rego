package cis_ubuntu_20_04.ssh_test

import rego.v1

# Validation fix pass 2026-10-17.

good_cfg := concat("\n", [
	"# comment",
	"AllowGroups ssh-users",
	"LogLevel VERBOSE",
	"PermitRootLogin no",
	"Banner /etc/issue.net",
	"MaxAuthTries 4",
	"MaxStartups 10:30:60",
	"MaxSessions 10",
	"LoginGraceTime 60",
	"ClientAliveInterval 300",
	"ClientAliveCountMax 0",
	"Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
	"MACs hmac-sha2-512-etm@openssh.com",
	"KexAlgorithms curve25519-sha256",
])

good_ssh := {
	"sshd_config_raw": good_cfg,
	"sshd_config_mode": "0600", "sshd_config_owner": "root", "sshd_config_group": "root",
	"private_key_files": [{"path": "/etc/ssh/ssh_host_ed25519_key", "mode": "0600"}],
	"public_key_files": [{"path": "/etc/ssh/ssh_host_ed25519_key.pub", "mode": "0644"}],
}

with_cfg(extra) := {"ssh": object.union(good_ssh, {"sshd_config_raw": concat("\n", [good_cfg, extra])})}

# directive replaced rather than appended (first occurrence wins in sshd)
with_prefix(first) := {"ssh": object.union(good_ssh, {"sshd_config_raw": concat("\n", [first, good_cfg])})}

test_good_config_compliant if {
	data.cis_ubuntu_20_04.ssh.compliant with input as {"ssh": good_ssh}
}

test_empty_input_not_compliant if {
	not data.cis_ubuntu_20_04.ssh.compliant with input as {}
	some m in data.cis_ubuntu_20_04.ssh.violations with input as {}
	contains(m, "evidence missing")
}

test_commented_line_does_not_mask_active_directive if {
	cfg := concat("\n", ["#PermitRootLogin no", "PermitRootLogin yes", "AllowGroups g", "LogLevel INFO"])
	v := data.cis_ubuntu_20_04.ssh.config_violations with input as {"ssh": object.union(good_ssh, {"sshd_config_raw": cfg})}
	"CIS 5.2.7: SSH root login is not disabled" in v
}

test_commented_secure_value_does_not_satisfy if {
	cfg := "# PermitRootLogin no\n# LogLevel INFO\n# Banner /etc/issue.net"
	v := data.cis_ubuntu_20_04.ssh.config_violations with input as {"ssh": object.union(good_ssh, {"sshd_config_raw": cfg})}
	"CIS 5.2.7: SSH root login is not disabled" in v
	"CIS 5.2.5: SSH LogLevel is not set to VERBOSE or INFO" in v
	"CIS 5.2.14: SSH warning banner (Banner) is not configured" in v
}

test_first_occurrence_wins if {
	v := data.cis_ubuntu_20_04.ssh.config_violations with input as with_prefix("PermitRootLogin yes")
	"CIS 5.2.7: SSH root login is not disabled" in v
}

test_directive_after_match_block_ignored if {
	cfg := concat("\n", [good_cfg, "Match User backup", "PermitRootLogin yes", "X11Forwarding yes"])
	v := data.cis_ubuntu_20_04.ssh.config_violations with input as {"ssh": object.union(good_ssh, {"sshd_config_raw": cfg})}
	count(v) == 0
}

test_tab_separated_max_auth_tries if {
	cfg := concat("\n", ["MaxAuthTries\t10", good_cfg])
	v := data.cis_ubuntu_20_04.ssh.config_violations with input as {"ssh": object.union(good_ssh, {"sshd_config_raw": cfg})}
	"CIS 5.2.15: SSH MaxAuthTries is 10, should be 4 or less" in v
}

test_tab_separated_sessions_and_grace_time if {
	cfg := concat("\n", ["MaxSessions\t20", "LoginGraceTime\t2m", good_cfg])
	v := data.cis_ubuntu_20_04.ssh.config_violations with input as {"ssh": object.union(good_ssh, {"sshd_config_raw": cfg})}
	"CIS 5.2.17: SSH MaxSessions is 20, should be 10 or less" in v
	"CIS 5.2.18: SSH LoginGraceTime is 2m seconds, should be 60 or less" in v
}

test_case_insensitive_keyword_and_equals_separator if {
	v := data.cis_ubuntu_20_04.ssh.config_violations with input as with_prefix("x11forwarding = yes")
	"CIS 5.2.12: SSH X11Forwarding is enabled" in v
}

test_missing_max_auth_tries_flagged_as_default_is_6 if {
	cfg := replace(good_cfg, "MaxAuthTries 4", "")
	v := data.cis_ubuntu_20_04.ssh.config_violations with input as {"ssh": object.union(good_ssh, {"sshd_config_raw": cfg})}
	some m in v
	startswith(m, "CIS 5.2.15: SSH MaxAuthTries is not configured")
}

test_private_key_mode_0044_and_0640_flagged if {
	every m in ["0044", "0640", "0644", "bogus"] {
		inp := {"ssh": object.union(good_ssh, {"private_key_files": [{"path": "/k", "mode": m}]})}
		v := data.cis_ubuntu_20_04.ssh.permission_violations with input as inp
		count(v) == 1
	}
}

test_private_key_restrictive_modes_ok if {
	every m in ["0600", "600", "0400", "0000"] {
		inp := {"ssh": object.union(good_ssh, {"private_key_files": [{"path": "/k", "mode": m}]})}
		v := data.cis_ubuntu_20_04.ssh.permission_violations with input as inp
		count(v) == 0
	}
}

test_weak_cipher_exact_token_only if {
	v := data.cis_ubuntu_20_04.ssh.crypto_violations with input as with_prefix("Ciphers aes128-cbc,aes256-gcm@openssh.com")
	v == {"CIS 5.2.20: SSH configuration contains weak cipher: aes128-cbc"}
	v2 := data.cis_ubuntu_20_04.ssh.crypto_violations with input as with_prefix("MACs hmac-sha1-etm@openssh.com")
	count(v2) == 0
	v3 := data.cis_ubuntu_20_04.ssh.crypto_violations with input as with_prefix("MACs hmac-sha1,hmac-sha2-256")
	count(v3) == 1
}

test_missing_key_files_flagged if {
	inp := {"ssh": json.remove(good_ssh, ["private_key_files", "public_key_files"])}
	v := data.cis_ubuntu_20_04.ssh.permission_violations with input as inp
	count(v) == 2
}
