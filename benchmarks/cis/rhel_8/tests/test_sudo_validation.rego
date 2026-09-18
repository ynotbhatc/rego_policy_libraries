package cis_rhel8.sudo_test

import rego.v1

import data.cis_rhel8.sudo

# Unit tests for benchmarks/cis/rhel_8/sudo_validation.rego (package cis_rhel8.sudo).
# CIS RHEL 8 Benchmark v4.0.0 - Section 5.3: Configure privilege escalation.
# One test per violation rule (input crafted so exactly that rule fires),
# plus a compliant-input test and an empty-input report test.
# Closes issue #77. No lab IPs — none needed here.

# A fully compliant sudo fact set. Each violation test mutates one field.
compliant_input := {"sudo": {
	"installed": true,
	"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
	"logfile_exists": true,
	"timestamp_timeout": "10",
	"su_restricted": true,
	"wheel_group_members": ["alice"],
	"sudoers_mode": "0440",
	"sudoers_owner": "root",
	"sudoers_group": "root",
}}

# --- One test per violation rule --------------------------------------------

# CIS 5.3.1: sudo package not installed
test_5_3_1_sudo_not_installed if {
	violations := sudo.violations with input as {"sudo": {
		"installed": false,
		"sudoers_content": "",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "CIS 5.3.1")
}

# CIS 5.3.2: sudo not configured to use pty
test_5_3_2_use_pty_missing if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "CIS 5.3.2")
}

# CIS 5.3.3: sudo logfile not configured (option missing)
test_5_3_3_logfile_option_missing if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\n@includedir /etc/sudoers.d",
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "missing")
}

# CIS 5.3.3: logfile configured but the file does not exist
test_5_3_3_logfile_file_missing if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": false,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "does not exist")
}

# CIS 5.3.4: NOPASSWD option found in sudoers
test_5_3_4_nopasswd_present if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nalice ALL=(ALL) NOPASSWD: ALL\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "CIS 5.3.4")
}

# CIS 5.3.5: !authenticate found in sudoers
test_5_3_5_authenticate_disabled if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults !authenticate\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "CIS 5.3.5")
}

# CIS 5.3.6: timestamp_timeout greater than 15 minutes
test_5_3_6_timeout_too_high if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "30",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "minutes")
}

# CIS 5.3.6: timestamp_timeout not configured at all
test_5_3_6_timeout_not_configured if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "not configured")
}

# CIS 5.3.7: access to su command not restricted
test_5_3_7_su_not_restricted if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": false,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "not restricted")
}

# CIS 5.3.7: wheel group has no members
test_5_3_7_wheel_group_empty if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": [],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "wheel group has no members")
}

# CIS 5.3: /etc/sudoers has wrong mode
test_5_3_sudoers_bad_mode if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0777",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "mode 0777")
}

# CIS 5.3: /etc/sudoers has wrong owner
test_5_3_sudoers_bad_owner if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "bob",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "owned by bob")
}

# CIS 5.3: /etc/sudoers has wrong group
test_5_3_sudoers_bad_group if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "staff",
	}}
	some msg in violations
	contains(msg, "group is staff")
}

# CIS 5.3: sudoers should include /etc/sudoers.d directory
test_5_3_missing_includedir if {
	violations := sudo.violations with input as {"sudo": {
		"installed": true,
		"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log",
		"logfile_exists": true,
		"timestamp_timeout": "10",
		"su_restricted": true,
		"wheel_group_members": ["alice"],
		"sudoers_mode": "0440",
		"sudoers_owner": "root",
		"sudoers_group": "root",
	}}
	some msg in violations
	contains(msg, "include /etc/sudoers.d")
}

# --- Compliant input --------------------------------------------------------

# A fully compliant sudo config yields zero violations and compliant = true.
test_compliant_input_no_violations if {
	count(sudo.violations) == 0 with input as compliant_input
	sudo.compliant with input as compliant_input
}

# --- Report shape on empty input --------------------------------------------

# The report must be a populated object even on empty input (never the
# undefined -> {} collapse), and report non-compliance.
test_report_populated_on_empty_input if {
	report := sudo.report with input as {}
	is_object(report)
	count(report) > 0
	report.benchmark == "CIS RHEL 8 v4.0.0"
	report.total_violations > 0
	report.compliant == false
}
