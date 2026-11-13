package cis_rocky_linux_8.ssh_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass (octal modes).

has(prefix, v) if {
	some m in v
	startswith(m, prefix)
}

test_ssh_config_mode_0400_ok if {
	v := data.cis_rocky_linux_8.ssh.permission_violations with input as {"ssh": {"config_permissions": {"mode": "0400", "pw_name": "root", "gr_name": "root"}}}
	not has("CIS 5.2.1", v)
}

test_ssh_config_mode_0640_flagged if {
	v := data.cis_rocky_linux_8.ssh.permission_violations with input as {"ssh": {"config_permissions": {"mode": "0640", "pw_name": "root", "gr_name": "root"}}}
	has("CIS 5.2.1", v)
}

test_ssh_config_mode_missing_flagged if {
	v := data.cis_rocky_linux_8.ssh.permission_violations with input as {"ssh": {"config_permissions": {"pw_name": "root", "gr_name": "root"}}}
	has("CIS 5.2.1: evidence missing", v)
}

test_ssh_private_key_0400_ok if {
	i := {"ssh": {"private_key_permissions": [{"stat": {"path": "/etc/ssh/k", "mode": "0400", "pw_name": "root"}}]}}
	v := data.cis_rocky_linux_8.ssh.permission_violations with input as i
	not has("CIS 5.2.2", v)
}

test_ssh_private_key_0640_flagged if {
	i := {"ssh": {"private_key_permissions": [{"stat": {"path": "/etc/ssh/k", "mode": "0640", "pw_name": "root"}}]}}
	v := data.cis_rocky_linux_8.ssh.permission_violations with input as i
	has("CIS 5.2.2", v)
}

test_ssh_public_key_0664_flagged if {
	v := data.cis_rocky_linux_8.ssh.permission_violations with input as {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0664"}]}}
	has("CIS 5.2.3", v)
}

test_ssh_public_key_0644_ok if {
	v := data.cis_rocky_linux_8.ssh.permission_violations with input as {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0644"}]}}
	not has("CIS 5.2.3", v)
}

test_ssh_public_key_0607_flagged if {
	v := data.cis_rocky_linux_8.ssh.permission_violations with input as {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0607"}]}}
	has("CIS 5.2.3", v)
}

# Semantic review 2026-11-13: LoginGraceTime 0 disables the limit and must not pass.
test_logingracetime_zero_flagged if {
	v := data.cis_rocky_linux_8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nlogingracetime 0\n"}}
	some x in v
	contains(x, "LoginGraceTime is 0")
}

test_logingracetime_sixty_not_flagged_as_zero if {
	v := data.cis_rocky_linux_8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nlogingracetime 60\n"}}
	every x in v {
		not contains(x, "LoginGraceTime is 0")
	}
}

test_clientaliveinterval_zero_flagged if {
	v := data.cis_rocky_linux_8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nclientaliveinterval 0\n"}}
	some x in v
	contains(x, "ClientAliveInterval is 0")
}

test_logingracetime_missing_flagged if {
	v := data.cis_rocky_linux_8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\n"}}
	some x in v
	contains(x, "LoginGraceTime not configured")
}

test_clientalivecountmax_zero_flagged if {
	v := data.cis_rocky_linux_8.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nclientalivecountmax 0\n"}}
	some x in v
	contains(x, "ClientAliveCountMax is 0")
}
