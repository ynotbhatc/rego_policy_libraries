package cis.access_control_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

ssh_good := [
	"AllowUsers admin",
	"LogLevel INFO",
	"X11Forwarding no",
	"MaxAuthTries 4",
	"IgnoreRhosts yes",
	"HostbasedAuthentication no",
	"PermitRootLogin no",
	"PermitEmptyPasswords no",
	"PermitUserEnvironment no",
	"ClientAliveInterval 300",
	"ClientAliveCountMax 3",
	"LoginGraceTime 60",
	"Banner /etc/issue.net",
	"UsePAM yes",
	"AllowTcpForwarding no",
	"MaxStartups 10:30:60",
	"MaxSessions 10",
]

fp(mode) := {"mode": mode, "owner": "root", "group": "root"}

good := {
	"services": {"cron": {"enabled": true}},
	"ssh_config": ssh_good,
	"ssh_private_keys": ["/etc/ssh/ssh_host_rsa_key"],
	"ssh_public_keys": ["/etc/ssh/ssh_host_rsa_key.pub"],
	"file_permissions": {
		"/etc/crontab": fp("0600"),
		"/etc/cron.hourly": fp("0700"),
		"/etc/cron.daily": fp("0700"),
		"/etc/cron.weekly": fp("0700"),
		"/etc/cron.monthly": fp("0700"),
		"/etc/ssh/sshd_config": fp("0600"),
		"/etc/ssh/ssh_host_rsa_key": fp("0600"),
		"/etc/ssh/ssh_host_rsa_key.pub": fp("0644"),
	},
}

test_access_control_array_input_compliant if {
	data.cis.access_control.access_control_compliant with input as good
}

test_access_control_string_input_compliant if {
	i := object.union(good, {"ssh_config": concat("\n", ssh_good)})
	data.cis.access_control.access_control_compliant with input as i
}

test_access_control_array_x11_and_loglevel_evaluated if {
	data.cis.access_control.ssh_x11_forwarding_disabled with input as good
	data.cis.access_control.ssh_loglevel_appropriate with input as good
	data.cis.access_control.ssh_pam_enabled with input as good
}

test_access_control_x11_yes_flagged if {
	i := object.union(good, {"ssh_config": ["X11Forwarding yes"]})
	not data.cis.access_control.ssh_x11_forwarding_disabled with input as i
}

test_access_control_crypto_policy_override_flagged if {
	i := object.union(good, {"ssh_config": array.concat(ssh_good, ["Include CRYPTO_POLICY override"])})
	not data.cis.access_control.ssh_crypto_policy_not_overridden with input as i
}

test_access_control_crypto_policy_no_evidence_fails if {
	not data.cis.access_control.ssh_crypto_policy_not_overridden with input as {}
}

test_access_control_empty_private_key_list_fails if {
	i := object.union(good, {"ssh_private_keys": []})
	not data.cis.access_control.ssh_private_key_permissions with input as i
}

test_access_control_max_startups_stub_replaced if {
	i := object.union(good, {"ssh_config": ["MaxStartups 100:100:100"]})
	not data.cis.access_control.ssh_max_startups_configured with input as i
}

test_access_control_max_startups_default_ok if {
	i := object.union(good, {"ssh_config": ["MaxStartups 10:30:60"]})
	data.cis.access_control.ssh_max_startups_configured with input as i
}

test_access_control_stricter_modes_ok if {
	i := object.union(good, {"file_permissions": {"/etc/crontab": fp("0400"), "/etc/ssh/sshd_config": fp("0400")}})
	data.cis.access_control.crontab_permissions with input as i
	data.cis.access_control.sshd_config_permissions with input as i
}

test_access_control_report_populated_on_empty_input if {
	r := data.cis.access_control.access_control_compliance with input as {}
	count(r) == 27
	r.overall_compliant == false
}
