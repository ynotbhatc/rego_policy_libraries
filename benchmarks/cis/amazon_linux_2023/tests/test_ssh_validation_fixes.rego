package cis_amazon_linux_2023.ssh_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass (octal modes).

has(prefix, v) if {
	some m in v
	startswith(m, prefix)
}

test_ssh_config_mode_0400_ok if {
	v := data.cis_amazon_linux_2023.ssh.permission_violations with input as {"ssh": {"config_permissions": {"mode": "0400", "pw_name": "root", "gr_name": "root"}}}
	not has("CIS 5.2.1", v)
}

test_ssh_config_mode_0640_flagged if {
	v := data.cis_amazon_linux_2023.ssh.permission_violations with input as {"ssh": {"config_permissions": {"mode": "0640", "pw_name": "root", "gr_name": "root"}}}
	has("CIS 5.2.1", v)
}

test_ssh_config_mode_missing_flagged if {
	v := data.cis_amazon_linux_2023.ssh.permission_violations with input as {"ssh": {"config_permissions": {"pw_name": "root", "gr_name": "root"}}}
	has("CIS 5.2.1: evidence missing", v)
}

test_ssh_private_key_0400_ok if {
	i := {"ssh": {"private_key_permissions": [{"stat": {"path": "/etc/ssh/k", "mode": "0400", "pw_name": "root"}}]}}
	v := data.cis_amazon_linux_2023.ssh.permission_violations with input as i
	not has("CIS 5.2.2", v)
}

test_ssh_private_key_0640_flagged if {
	i := {"ssh": {"private_key_permissions": [{"stat": {"path": "/etc/ssh/k", "mode": "0640", "pw_name": "root"}}]}}
	v := data.cis_amazon_linux_2023.ssh.permission_violations with input as i
	has("CIS 5.2.2", v)
}

test_ssh_public_key_0664_flagged if {
	v := data.cis_amazon_linux_2023.ssh.permission_violations with input as {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0664"}]}}
	has("CIS 5.2.3", v)
}

test_ssh_public_key_0644_ok if {
	v := data.cis_amazon_linux_2023.ssh.permission_violations with input as {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0644"}]}}
	not has("CIS 5.2.3", v)
}

test_ssh_public_key_0607_flagged if {
	v := data.cis_amazon_linux_2023.ssh.permission_violations with input as {"ssh": {"public_key_permissions": [{"path": "/etc/ssh/k.pub", "mode": "0607"}]}}
	has("CIS 5.2.3", v)
}
