package cis_ubuntu_24_04.ssh_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good_raw := concat("\n", [
	"# stock comments",
	"#PermitRootLogin prohibit-password",
	"AllowUsers admin",
	"LogLevel VERBOSE",
	"UsePAM yes",
	"PermitRootLogin no",
	"Banner /etc/issue.net",
	"MaxAuthTries 4",
	"MaxStartups 10:30:60",
	"MaxSessions 10",
	"LoginGraceTime 60",
	"ClientAliveInterval 300",
	"ClientAliveCountMax 3",
])

good := {"ssh": {
	"sshd_config_raw": good_raw,
	"sshd_config_mode": "0600", "sshd_config_owner": "root", "sshd_config_group": "root",
	"private_key_files": [{"path": "/etc/ssh/ssh_host_rsa_key", "mode": "0600"}],
	"public_key_files": [{"path": "/etc/ssh/ssh_host_rsa_key.pub", "mode": "0644"}],
}}

with_raw(raw) := object.union(good, {"ssh": {"sshd_config_raw": raw}})

test_ssh_fully_evidenced_is_compliant if {
	data.cis_ubuntu_24_04.ssh.compliant with input as good
}

test_ssh_empty_input_is_not_compliant if {
	not data.cis_ubuntu_24_04.ssh.compliant with input as {}
	"CIS 5.2: evidence missing — ssh.sshd_config_raw not collected" in data.cis_ubuntu_24_04.ssh.config_violations with input as {}
}

test_ssh_private_key_mode_octal if {
	every m in ["0444", "0440", "0604", "0644"] {
		i := object.union(good, {"ssh": {"private_key_files": [{"path": "k", "mode": m}]}})
		not data.cis_ubuntu_24_04.ssh.compliant with input as i
	}
	every m in ["0600", "0400"] {
		i := object.union(good, {"ssh": {"private_key_files": [{"path": "k", "mode": m}]}})
		data.cis_ubuntu_24_04.ssh.compliant with input as i
	}
}

test_ssh_public_key_mode_octal if {
	i := object.union(good, {"ssh": {"public_key_files": [{"path": "k.pub", "mode": "0622"}]}})
	not data.cis_ubuntu_24_04.ssh.compliant with input as i
	j := object.union(good, {"ssh": {"public_key_files": [{"path": "k.pub", "mode": "0600"}]}})
	data.cis_ubuntu_24_04.ssh.compliant with input as j
}

test_ssh_commented_permitrootlogin_does_not_satisfy if {
	raw := "#PermitRootLogin prohibit-password\nPermitRootLogin yes\nLogLevel INFO"
	"CIS 5.2.7: SSH root login is not disabled" in data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw)
}

test_ssh_commented_loglevel_does_not_satisfy if {
	raw := concat("\n", [good_raw, "#LogLevel INFO"])
	raw2 := replace(raw, "LogLevel VERBOSE", "LogLevel DEBUG")
	"CIS 5.2.5: SSH LogLevel is not set to VERBOSE or INFO" in data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw2)
}

test_ssh_commented_banner_none_is_not_a_violation if {
	raw := concat("\n", [good_raw, "#Banner none"])
	v := data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw)
	not "CIS 5.2.14: SSH banner is set to none" in v
	count(v) == 0
}

test_ssh_banner_none_active_is_violation if {
	raw := replace(good_raw, "Banner /etc/issue.net", "Banner none")
	"CIS 5.2.14: SSH banner is set to none" in data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw)
}

test_ssh_commented_directives_do_not_satisfy_required_settings if {
	raw := "Port 22\n#AllowUsers x\n#Banner /x\n#MaxStartups 10\n#ClientAliveInterval 1\n#ClientAliveCountMax 1"
	v := data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw)
	"CIS 5.2.16: SSH MaxStartups is not configured" in v
	"CIS 5.2.4: SSH access is not limited via AllowUsers/AllowGroups/DenyUsers/DenyGroups" in v
}

test_ssh_x11_forwarding_yes_in_comment_ignored_but_active_flagged if {
	raw := concat("\n", [good_raw, "X11Forwarding yes"])
	"CIS 5.2.12: SSH X11Forwarding is enabled" in data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw)
	raw2 := concat("\n", [good_raw, "# X11Forwarding yes"])
	not "CIS 5.2.12: SSH X11Forwarding is enabled" in data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw2)
}

test_ssh_max_auth_tries_over_limit if {
	raw := replace(good_raw, "MaxAuthTries 4", "MaxAuthTries 6")
	"CIS 5.2.15: SSH MaxAuthTries is 6, should be 4 or less" in data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw)
}

test_ssh_login_grace_time_minutes_suffix if {
	raw := replace(good_raw, "LoginGraceTime 60", "LoginGraceTime 2m")
	"CIS 5.2.18: SSH LoginGraceTime is 2m seconds, should be 60 or less" in data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw)
}

test_ssh_key_equals_form_parsed if {
	raw := replace(good_raw, "PermitRootLogin no", "PermitRootLogin=yes")
	"CIS 5.2.7: SSH root login is not disabled" in data.cis_ubuntu_24_04.ssh.config_violations with input as with_raw(raw)
}

test_ssh_missing_config_file_attrs_are_violations if {
	every k in ["sshd_config_mode", "sshd_config_owner", "sshd_config_group", "private_key_files", "public_key_files"] {
		not data.cis_ubuntu_24_04.ssh.compliant with input as json.remove(good, [concat("/", ["ssh", k])])
	}
}

test_ssh_config_mode_octal if {
	data.cis_ubuntu_24_04.ssh.compliant with input as object.union(good, {"ssh": {"sshd_config_mode": "0400"}})
	not data.cis_ubuntu_24_04.ssh.compliant with input as object.union(good, {"ssh": {"sshd_config_mode": "0644"}})
}
