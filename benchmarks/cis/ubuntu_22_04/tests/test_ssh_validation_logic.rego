package cis_ubuntu_22_04.ssh_test

import rego.v1

# Validation fix 2026-10-17: compliant on empty input; comments/substrings satisfied checks;
# decimal key-mode compare; single-space-only numeric parsing.

pkg := data.cis_ubuntu_22_04.ssh

good_raw := concat("\n", [
	"allowusers admin",
	"loglevel VERBOSE",
	"usepam yes",
	"permitrootlogin no",
	"banner /etc/issue.net",
	"maxauthtries 4",
	"maxstartups 10:30:60",
	"maxsessions 10",
	"logingracetime 60",
	"clientaliveinterval 300",
	"clientalivecountmax 3",
	"ciphers aes256-ctr,aes128-gcm@openssh.com",
	"macs hmac-sha2-512-etm@openssh.com",
	"kexalgorithms curve25519-sha256",
])

good := {"ssh": {
	"sshd_config_raw": good_raw,
	"sshd_config_mode": "0600", "sshd_config_owner": "root", "sshd_config_group": "root",
	"private_key_files": [{"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0600"}],
	"public_key_files": [{"path": "/etc/ssh/ssh_host_rsa_key.pub", "mode": "0644"}],
}}

with_raw(extra) := object.union(good, {"ssh": {"sshd_config_raw": concat("\n", [good_raw, extra])}})

# first occurrence wins in sshd, so overrides are prepended
with_first(line) := object.union(good, {"ssh": {"sshd_config_raw": concat("\n", [line, good_raw])}})

test_empty_input_not_compliant if {
	not pkg.compliant with input as {}
}

test_good_compliant if {
	pkg.compliant with input as good
}

test_commented_default_does_not_hide_active_root_login if {
	raw := concat("\n", ["#PermitRootLogin prohibit-password", "PermitRootLogin yes", good_raw])
	v := pkg.config_violations with input as object.union(good, {"ssh": {"sshd_config_raw": raw}})
	"CIS 5.2.7: SSH root login is not disabled" in v
}

test_commented_banner_none_is_not_a_violation if {
	raw := concat("\n", ["#Banner none", good_raw])
	pkg.compliant with input as object.union(good, {"ssh": {"sshd_config_raw": raw}})
}

test_active_banner_none_violates if {
	v := pkg.config_violations with input as with_first("Banner none")
	"CIS 5.2.14: SSH banner is set to none" in v
}

test_double_space_and_tab_max_auth_tries if {
	v1 := pkg.config_violations with input as with_first("MaxAuthTries  10")
	"CIS 5.2.15: SSH MaxAuthTries is 10, should be 4 or less" in v1
	v2 := pkg.config_violations with input as with_first("MaxAuthTries\t10")
	"CIS 5.2.15: SSH MaxAuthTries is 10, should be 4 or less" in v2
}

test_equals_separator_and_case if {
	v := pkg.config_violations with input as with_first("PERMITROOTLOGIN=yes")
	"CIS 5.2.7: SSH root login is not disabled" in v
}

test_login_grace_time_minutes if {
	v := pkg.config_violations with input as with_first("LoginGraceTime 2m")
	"CIS 5.2.18: SSH LoginGraceTime is 2m seconds, should be 60 or less" in v
	pkg.compliant with input as with_first("LoginGraceTime 1m")
}

test_max_auth_tries_unset_violates if {
	raw := replace(good_raw, "maxauthtries 4\n", "")
	not pkg.compliant with input as object.union(good, {"ssh": {"sshd_config_raw": raw}})
}

test_private_key_mode_0570_violates if {
	inp := object.union(good, {"ssh": {"private_key_files": [{"path": "/k", "mode": "0570"}]}})
	not pkg.compliant with input as inp
}

test_public_key_mode_0622_violates if {
	inp := object.union(good, {"ssh": {"public_key_files": [{"path": "/k.pub", "mode": "0622"}]}})
	not pkg.compliant with input as inp
}

test_key_without_mode_violates if {
	inp := object.union(good, {"ssh": {"private_key_files": [{"path": "/k"}]}})
	not pkg.compliant with input as inp
}

test_config_permission_fields_required if {
	every field in ["sshd_config_mode", "sshd_config_owner", "sshd_config_group", "private_key_files", "public_key_files"] {
		not pkg.compliant with input as {"ssh": object.remove(good.ssh, [field])}
	}
}

test_weak_algorithms_exact_tokens if {
	v := pkg.crypto_violations with input as with_first("Ciphers aes128-cbc,aes256-ctr")
	"CIS 5.2.20: SSH configuration contains weak cipher: aes128-cbc" in v
	count(pkg.crypto_violations) == 0 with input as with_first("Ciphers aes256-ctr,-3des-cbc")
	m := pkg.crypto_violations with input as with_first("MACs hmac-sha1-etm@openssh.com")
	"CIS 5.2.21: SSH configuration contains weak MAC algorithm: hmac-sha1-etm@openssh.com" in m
}

test_no_access_limit_violates if {
	raw := replace(good_raw, "allowusers admin\n", "")
	not pkg.compliant with input as object.union(good, {"ssh": {"sshd_config_raw": raw}})
}
