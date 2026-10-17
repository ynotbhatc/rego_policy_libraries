package cis_debian_11.ssh_test

import rego.v1

conf := concat("\n", [
	"AllowUsers admin",
	"LogLevel VERBOSE",
	"PermitRootLogin no",
	"Banner /etc/issue.net",
	"MaxAuthTries 4",
	"MaxStartups 10:30:60",
	"MaxSessions 10",
	"LoginGraceTime 1m",
	"ClientAliveInterval 300",
	"ClientAliveCountMax 3",
	"Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
	"",
])

good := {"ssh": {
	"sshd_config_raw": conf,
	"sshd_config_mode": "0600", "sshd_config_owner": "root", "sshd_config_group": "root",
	"private_key_files": [{"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0600"}],
	"public_key_files": [{"path": "/etc/ssh/ssh_host_rsa_key.pub", "mode": "0644"}],
}}

with_conf(c) := object.union(good, {"ssh": {"sshd_config_raw": c}})

test_good_compliant if {
	data.cis_debian_11.ssh.compliant with input as good
}

test_empty_input_not_compliant if {
	not data.cis_debian_11.ssh.compliant with input as {}
}

test_commented_allowusers_does_not_satisfy if {
	i := with_conf(replace(conf, "AllowUsers admin", "#AllowUsers admin"))
	some m in data.cis_debian_11.ssh.config_violations with input as i
	contains(m, "5.2.4")
}

test_login_grace_time_units if {
	i := with_conf(replace(conf, "LoginGraceTime 1m", "LoginGraceTime 2m"))
	some m in data.cis_debian_11.ssh.config_violations with input as i
	contains(m, "5.2.18")
}

test_login_grace_time_30s_ok if {
	data.cis_debian_11.ssh.compliant with input as with_conf(replace(conf, "LoginGraceTime 1m", "LoginGraceTime 30s"))
}

test_max_auth_tries_over_limit if {
	i := with_conf(replace(conf, "MaxAuthTries 4", "MaxAuthTries 6"))
	some m in data.cis_debian_11.ssh.config_violations with input as i
	contains(m, "5.2.15")
}

test_unset_max_auth_tries_violates if {
	i := with_conf(replace(conf, "MaxAuthTries 4\n", ""))
	some m in data.cis_debian_11.ssh.config_violations with input as i
	contains(m, "MaxAuthTries is not set")
}

test_permit_root_login_commented_violates if {
	i := with_conf(replace(conf, "PermitRootLogin no", "#PermitRootLogin no"))
	some m in data.cis_debian_11.ssh.config_violations with input as i
	contains(m, "5.2.7")
}

test_match_block_not_global if {
	i := with_conf(concat("\n", [conf, "Match User bob", "PermitRootLogin yes", ""]))
	data.cis_debian_11.ssh.compliant with input as i
	j := with_conf(concat("\n", ["Match User bob", "PermitRootLogin no", "", conf]))
	not data.cis_debian_11.ssh.compliant with input as j
}

test_weak_cipher_exact_token if {
	i := with_conf(replace(conf, "Ciphers aes256-gcm@openssh.com", "Ciphers aes128-cbc"))
	some m in data.cis_debian_11.ssh.crypto_violations with input as i
	contains(m, "aes128-cbc")
}

test_removed_weak_cipher_not_flagged if {
	i := with_conf(replace(conf, "Ciphers aes256-gcm@openssh.com", "Ciphers -aes128-cbc,aes256-gcm@openssh.com"))
	count(data.cis_debian_11.ssh.crypto_violations) == 0 with input as i
}

test_sha1_etm_mac_flagged if {
	i := with_conf(concat("\n", [conf, "MACs hmac-sha1-etm@openssh.com", ""]))
	some m in data.cis_debian_11.ssh.crypto_violations with input as i
	contains(m, "weak MAC")
}

test_key_modes_octal if {
	i := json.patch(good, [{"op": "replace", "path": "/ssh/private_key_files/0/mode", "value": "0640"}])
	some m in data.cis_debian_11.ssh.permission_violations with input as i
	contains(m, "5.2.2")
}

test_missing_key_evidence_violates if {
	not data.cis_debian_11.ssh.compliant with input as json.patch(good, [{"op": "remove", "path": "/ssh/private_key_files"}])
}

test_missing_config_mode_violates if {
	not data.cis_debian_11.ssh.compliant with input as json.patch(good, [{"op": "remove", "path": "/ssh/sshd_config_mode"}])
}
