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

# Semantic review 2026-11-13: LoginGraceTime 0 disables the limit and must not pass.
test_logingracetime_zero_flagged if {
	v := data.cis_rhel8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nlogingracetime 0\n"}}
	some x in v
	contains(x, "LoginGraceTime is 0")
}

test_logingracetime_sixty_not_flagged_as_zero if {
	v := data.cis_rhel8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nlogingracetime 60\n"}}
	every x in v {
		not contains(x, "LoginGraceTime is 0")
	}
}

test_clientaliveinterval_zero_flagged if {
	v := data.cis_rhel8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nclientaliveinterval 0\n"}}
	some x in v
	contains(x, "ClientAliveInterval is 0")
}

test_logingracetime_missing_flagged if {
	v := data.cis_rhel8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\n"}}
	some x in v
	contains(x, "LoginGraceTime not configured")
}

test_clientalivecountmax_zero_flagged if {
	v := data.cis_rhel8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nclientalivecountmax 0\n"}}
	some x in v
	contains(x, "ClientAliveCountMax is 0")
}
