package cis_rhel9.sudo_test

import rego.v1

import data.cis_rhel9.sudo

# Unit tests for benchmarks/cis/rhel_9/sudo_validation.rego (package cis_rhel9.sudo).
# Closes GitHub issue #76.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 5.3.x -> v3 5.2.x: 5.3.1->5.2.1, 5.3.2->5.2.4, 5.3.3->5.2.5, 5.3.4->5.2.6, 5.3.5->5.2.7,
# 5.3.6->5.2.10, 5.3.7->5.2.12, /etc/sudoers access (5.3)->5.2.2.
# Changed meaning in v3.0.0: an unset timestamp_timeout passes (sudo's compiled default of 5 minutes), and
# the su restriction is judged on the pam_wheel line only (the benchmark leaves group membership manual).

# A fully compliant sudo fact set. Each violation test overrides exactly one field of this baseline.
compliant_sudo := {
	"installed": true,
	"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
	"logfile_exists": true,
	"timestamp_timeout": "15",
	"su_restricted": true,
	"wheel_group_members": ["alice"],
	"sudoers_mode": "0440",
	"sudoers_owner": "root",
	"sudoers_group": "root",
	"sudoers_d_files": [{"path": "/etc/sudoers.d/admins", "mode": "0440", "owner": "root", "group": "root"}],
	"sudoers_d_dir": {"mode": "0750", "owner": "root", "group": "root"},
}

ids(vs, id) := [v | some v in vs; startswith(v, concat("", [id, ": "]))]

test_5_3_1_sudo_not_installed if {
	test_input := {"sudo": object.union(compliant_sudo, {"installed": false})}
	"5.2.1: not met — Ensure sudo is installed" in sudo.violations with input as test_input
}

test_5_3_2_use_pty_missing if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d"})}
	"5.2.4: not met — Ensure sudo commands use pty" in sudo.violations with input as test_input
}

test_5_3_3_logfile_not_configured if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults use_pty\n@includedir /etc/sudoers.d"})}
	"5.2.5: not met — Ensure sudo log file exists" in sudo.violations with input as test_input
}

test_5_3_3_logfile_missing_on_disk if {
	test_input := {"sudo": object.union(compliant_sudo, {"logfile_exists": false})}
	"5.2.5: not met — Ensure sudo log file exists" in sudo.violations with input as test_input
}

test_5_3_4_nopasswd_present if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d\n%wheel ALL=(ALL) NOPASSWD: ALL"})}
	"5.2.6: not met — Ensure users must provide password for escalation" in sudo.violations with input as test_input
}

test_5_3_5_reauthentication_disabled if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d\nDefaults !authenticate"})}
	"5.2.7: not met — Ensure re-authentication for privilege escalation is not disabled globally" in sudo.violations with input as test_input
}

test_5_3_6_timeout_too_high if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults timestamp_timeout=30"})}
	"5.2.10: not met — Ensure sudo timestamp_timeout is configured" in sudo.violations with input as test_input
}

# v3.0.0: no timestamp_timeout configured => sudo's compiled default of 5 minutes applies, which passes
test_5_3_6_timeout_not_configured if {
	test_input := {"sudo": object.remove(compliant_sudo, {"timestamp_timeout"})}
	count(ids(sudo.violations, "5.2.10")) == 0 with input as test_input
}

test_5_3_7_su_not_restricted if {
	test_input := {"sudo": object.union(compliant_sudo, {"su_restricted": false})}
	"5.2.12: not met — Ensure access to the su command is restricted" in sudo.violations with input as test_input
}

# v3.0.0: the automated check is the pam_wheel line; who is in the group is a manual step
test_5_3_7_wheel_group_empty if {
	test_input := {"sudo": object.union(compliant_sudo, {"wheel_group_members": []})}
	count(ids(sudo.violations, "5.2.12")) == 0 with input as test_input
}

test_5_3_sudoers_wrong_mode if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_mode": "0644"})}
	"5.2.2: not met — Ensure access on sudoers configuration files is configured" in sudo.violations with input as test_input
}

test_5_3_sudoers_wrong_owner if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_owner": "admin"})}
	"5.2.2: not met — Ensure access on sudoers configuration files is configured" in sudo.violations with input as test_input
}

test_5_3_sudoers_wrong_group if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_group": "wheel"})}
	"5.2.2: not met — Ensure access on sudoers configuration files is configured" in sudo.violations with input as test_input
}

test_compliant_input_has_no_violations if {
	count(sudo.violations) == 0 with input as {"sudo": compliant_sudo}
}

test_violations_populated_on_empty_input if {
	result := sudo.violations with input as {}
	is_set(result)
	count(result) > 0
}

# Validation fixes 2026-10-17: sudoers mode compared as octal bit mask; missing mode is a violation.
test_5_3_sudoers_mode_stricter_and_unpadded_ok if {
	every m in ["0440", "440", "0400", "0o440", "0000"] {
		i := object.union(compliant_sudo, {"sudoers_mode": m})
		sudo.compliant with input as {"sudo": i}
	}
}

test_5_3_sudoers_mode_group_write_flagged if {
	i := object.union(compliant_sudo, {"sudoers_mode": "0660"})
	not sudo.compliant with input as {"sudo": i}
}

test_5_3_sudoers_mode_missing_flagged if {
	i := json.remove(compliant_sudo, ["/sudoers_mode"])
	not sudo.compliant with input as {"sudo": i}
}

# a sudoers.d drop-in with a loose mode fails 5.2.2 even when /etc/sudoers itself is fine
test_5_2_2_sudoers_d_file_mode_flagged if {
	i := object.union(compliant_sudo, {"sudoers_d_files": [{"path": "/etc/sudoers.d/x", "mode": "0644", "owner": "root", "group": "root"}]})
	"5.2.2: not met — Ensure access on sudoers configuration files is configured" in sudo.violations with input as {"sudo": i}
}
