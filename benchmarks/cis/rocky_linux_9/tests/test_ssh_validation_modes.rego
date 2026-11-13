package cis_rocky_linux_9.ssh_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_rocky_linux_9.ssh.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_config_mode_0600_ok if not has("CIS 5.2.1: /etc/ssh/sshd_config permissions", {"ssh": {"config_permissions": {"mode": "0600"}}})
test_config_mode_0400_ok if not has("CIS 5.2.1: /etc/ssh/sshd_config permissions", {"ssh": {"config_permissions": {"mode": "0400"}}})
test_config_mode_0644_flagged if has("CIS 5.2.1: /etc/ssh/sshd_config permissions", {"ssh": {"config_permissions": {"mode": "0644"}}})
test_config_mode_absent_flagged if has("CIS 5.2.1: /etc/ssh/sshd_config permissions", {"ssh": {}})

test_private_key_0400_ok if not has("CIS 5.2.2: SSH private key", {"ssh": {"private_key_permissions": [{"stat": {"path": "/etc/ssh/k", "mode": "0400", "pw_name": "root"}}]}})
test_private_key_0640_flagged if has("CIS 5.2.2: SSH private key", {"ssh": {"private_key_permissions": [{"stat": {"path": "/etc/ssh/k", "mode": "0640", "pw_name": "root"}}]}})

test_public_key_0444_ok if not has("CIS 5.2.3", {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0444"}]}})
test_public_key_0666_flagged if has("CIS 5.2.3", {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0666"}]}})
test_public_key_0646_flagged if has("CIS 5.2.3", {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0646"}]}})

# Semantic review 2026-11-13: LoginGraceTime 0 disables the limit and must not pass.
test_logingracetime_zero_flagged if {
	v := data.cis_rocky_linux_9.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nlogingracetime 0\n"}}
	some x in v
	contains(x, "LoginGraceTime is 0")
}

test_logingracetime_sixty_not_flagged_as_zero if {
	v := data.cis_rocky_linux_9.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nlogingracetime 60\n"}}
	every x in v {
		not contains(x, "LoginGraceTime is 0")
	}
}

test_clientaliveinterval_zero_flagged if {
	v := data.cis_rocky_linux_9.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nclientaliveinterval 0\n"}}
	some x in v
	contains(x, "ClientAliveInterval is 0")
}

test_logingracetime_missing_flagged if {
	v := data.cis_rocky_linux_9.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\n"}}
	some x in v
	contains(x, "LoginGraceTime not configured")
}

test_clientalivecountmax_zero_flagged if {
	v := data.cis_rocky_linux_9.ssh.config_violations with input as {"ssh": {"sshd_config_raw": "port 22\nclientalivecountmax 0\n"}}
	some x in v
	contains(x, "ClientAliveCountMax is 0")
}
