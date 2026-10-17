package cis_rhel8.ssh_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes (octal mode comparison).

test_ssh_config_mode_stricter_accepted if {
	v := data.cis_rhel8.ssh.permission_violations with input as {"ssh": {"config_permissions": {"mode": "0400", "pw_name": "root", "gr_name": "root"}}}
	count(v) == 0
}

test_ssh_config_mode_looser_flagged if {
	v := data.cis_rhel8.ssh.permission_violations with input as {"ssh": {"config_permissions": {"mode": "0644", "pw_name": "root", "gr_name": "root"}}}
	"CIS 5.2.1: /etc/ssh/sshd_config permissions not 0600" in v
}

test_ssh_private_key_mode_stricter_accepted if {
	v := data.cis_rhel8.ssh.permission_violations with input as {"ssh": {"private_key_permissions": [{"stat": {"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0400", "pw_name": "root"}}]}}
	count(v) == 0
}

test_ssh_private_key_mode_looser_flagged if {
	v := data.cis_rhel8.ssh.permission_violations with input as {"ssh": {"private_key_permissions": [{"stat": {"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0640", "pw_name": "root"}}]}}
	count(v) == 1
}

test_ssh_public_key_mode_octal_not_decimal if {
	v := data.cis_rhel8.ssh.permission_violations with input as {"ssh": {"public_key_permissions": [{"path": "a.pub", "mode": "0622"}, {"path": "b.pub", "mode": "0600"}, {"path": "c.pub", "mode": "0644"}]}}
	count(v) == 1
}
