package cis_rhel9.ssh_test

import rego.v1

# Validation fixes 2026-10-17: key/config file modes are compared as octal bit masks.

perms(i) := v if {
	v := data.cis_rhel9.ssh.permission_violations with input as i
}

cfg := {"mode": "0600", "pw_name": "root", "gr_name": "root"}

test_ssh_config_stricter_mode_ok if {
	count(perms({"ssh": {"config_permissions": {"mode": "0400", "pw_name": "root", "gr_name": "root"}}})) == 0
}

test_ssh_config_mode_without_leading_zero_ok if {
	count(perms({"ssh": {"config_permissions": {"mode": "600", "pw_name": "root", "gr_name": "root"}}})) == 0
}

test_ssh_config_loose_mode_flagged if {
	count(perms({"ssh": {"config_permissions": {"mode": "0644", "pw_name": "root", "gr_name": "root"}}})) == 1
}

test_ssh_config_mode_missing_flagged if {
	"CIS 5.2.1: evidence missing — ssh.config_permissions.mode not collected" in perms({"ssh": {"config_permissions": {"pw_name": "root", "gr_name": "root"}}})
}

test_ssh_private_key_0400_ok if {
	count(perms({"ssh": {"config_permissions": cfg, "private_key_permissions": [{"stat": {"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0400", "pw_name": "root"}}]}})) == 0
}

test_ssh_private_key_0640_flagged if {
	count(perms({"ssh": {"config_permissions": cfg, "private_key_permissions": [{"stat": {"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0640", "pw_name": "root"}}]}})) == 1
}

test_ssh_public_key_0444_ok if {
	count(perms({"ssh": {"config_permissions": cfg, "public_key_permissions": [{"path": "/etc/ssh/a.pub", "mode": "0444"}]}})) == 0
}

test_ssh_public_key_0477_flagged if {
	count(perms({"ssh": {"config_permissions": cfg, "public_key_permissions": [{"path": "/etc/ssh/a.pub", "mode": "0477"}]}})) == 1
}

test_ssh_public_key_0664_flagged if {
	count(perms({"ssh": {"config_permissions": cfg, "public_key_permissions": [{"path": "/etc/ssh/a.pub", "mode": "0664"}]}})) == 1
}
