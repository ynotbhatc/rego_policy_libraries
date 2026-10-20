package cis_rhel9.ssh_test

import rego.v1

# Validation fixes 2026-10-17: key/config file modes are compared as octal bit masks.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 5.2.1-5.2.3 -> v3 5.1.1 (sshd_config + drop-ins), 5.1.3 (private host keys), 5.1.4 (public host keys).

perms(i) := v if {
	v := data.cis_rhel9.ssh.permission_violations with input as i
}

ids(vs, id) := [v | some v in vs; startswith(v, concat("", [id, ": "]))]

cfg := {"mode": "0600", "pw_name": "root", "gr_name": "root"}

test_ssh_config_stricter_mode_ok if {
	count(ids(perms({"ssh": {"config_permissions": {"mode": "0400", "pw_name": "root", "gr_name": "root"}, "dropin_permissions": []}}), "5.1.1")) == 0
}

test_ssh_config_mode_without_leading_zero_ok if {
	count(ids(perms({"ssh": {"config_permissions": {"mode": "600", "pw_name": "root", "gr_name": "root"}, "dropin_permissions": []}}), "5.1.1")) == 0
}

test_ssh_config_loose_mode_flagged if {
	count(ids(perms({"ssh": {"config_permissions": {"mode": "0644", "pw_name": "root", "gr_name": "root"}, "dropin_permissions": []}}), "5.1.1")) == 1
}

test_ssh_config_mode_missing_flagged if {
	"5.1.1: evidence missing — ssh.config_permissions/dropin_permissions not collected" in perms({"ssh": {"config_permissions": {"pw_name": "root", "gr_name": "root"}, "dropin_permissions": []}})
}

test_ssh_private_key_0400_ok if {
	count(ids(perms({"ssh": {"config_permissions": cfg, "private_key_permissions": [{"stat": {"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0400", "pw_name": "root", "gr_name": "root"}}]}}), "5.1.3")) == 0
}

test_ssh_private_key_0640_flagged if {
	count(ids(perms({"ssh": {"config_permissions": cfg, "private_key_permissions": [{"stat": {"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0640", "pw_name": "root", "gr_name": "root"}}]}}), "5.1.3")) == 1
}

test_ssh_public_key_0444_ok if {
	count(ids(perms({"ssh": {"config_permissions": cfg, "public_key_permissions": [{"path": "/etc/ssh/a.pub", "mode": "0444", "pw_name": "root", "gr_name": "root"}]}}), "5.1.4")) == 0
}

test_ssh_public_key_0477_flagged if {
	count(ids(perms({"ssh": {"config_permissions": cfg, "public_key_permissions": [{"path": "/etc/ssh/a.pub", "mode": "0477", "pw_name": "root", "gr_name": "root"}]}}), "5.1.4")) == 1
}

test_ssh_public_key_0664_flagged if {
	count(ids(perms({"ssh": {"config_permissions": cfg, "public_key_permissions": [{"path": "/etc/ssh/a.pub", "mode": "0664", "pw_name": "root", "gr_name": "root"}]}}), "5.1.4")) == 1
}

# 5.1.9: the banner file's text may come from initial_setup's /etc/issue.net flag
test_ssh_banner_text_from_issue_net_flag if {
	vs := data.cis_rhel9.ssh.violations with input as {"ssh": {"sshd_config_raw": "banner /etc/issue.net"}, "initial_setup": {"issue_net_contains_sensitive_info": false}}
	count(ids(vs, "5.1.9")) == 0
	vs2 := data.cis_rhel9.ssh.violations with input as {"ssh": {"sshd_config_raw": "banner /etc/issue.net"}, "initial_setup": {"issue_net_contains_sensitive_info": true}}
	"5.1.9: not met — Ensure sshd Banner is configured" in vs2
}
