package cis_rhel9.sudo_test

import rego.v1

import data.cis_rhel9.sudo

# Unit tests for benchmarks/cis/rhel_9/sudo_validation.rego (package cis_rhel9.sudo).
# Closes GitHub issue #76.
#
# The module exposes a `violations` set and a `compliant` boolean. It does NOT
# define a `compliance_report` object, so the "populated report object" contract
# test is applied to the `violations` set instead (see the empty-input test at
# the bottom). One test per `violations contains msg if { ... }` rule.

# A fully compliant sudo fact set. Each violation test overrides exactly one
# field of this baseline so the target rule fires in isolation.
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
}

# CIS 5.3.1 — sudo package not installed
test_5_3_1_sudo_not_installed if {
	test_input := {"sudo": object.union(compliant_sudo, {"installed": false})}
	"CIS 5.3.1: sudo package not installed" in sudo.violations with input as test_input
}

# CIS 5.3.2 — sudo not configured to use pty
test_5_3_2_use_pty_missing if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d"})}
	"CIS 5.3.2: sudo not configured to use pty (Defaults use_pty missing)" in sudo.violations with input as test_input
}

# CIS 5.3.3 — sudo logfile not configured
test_5_3_3_logfile_not_configured if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults use_pty\n@includedir /etc/sudoers.d"})}
	"CIS 5.3.3: sudo logfile not configured (Defaults logfile= missing)" in sudo.violations with input as test_input
}

# CIS 5.3.3 — logfile configured but file does not exist
test_5_3_3_logfile_missing_on_disk if {
	test_input := {"sudo": object.union(compliant_sudo, {"logfile_exists": false})}
	"CIS 5.3.3: sudo logfile configured but file does not exist" in sudo.violations with input as test_input
}

# CIS 5.3.4 — NOPASSWD present
test_5_3_4_nopasswd_present if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d\n%wheel ALL=(ALL) NOPASSWD: ALL"})}
	"CIS 5.3.4: NOPASSWD option found in sudoers - users should provide password" in sudo.violations with input as test_input
}

# CIS 5.3.5 — !authenticate present
test_5_3_5_reauthentication_disabled if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\n@includedir /etc/sudoers.d\nDefaults !authenticate"})}
	"CIS 5.3.5: !authenticate found in sudoers - re-authentication is disabled" in sudo.violations with input as test_input
}

# CIS 5.3.6 — timestamp_timeout greater than 15
test_5_3_6_timeout_too_high if {
	test_input := {"sudo": object.union(compliant_sudo, {"timestamp_timeout": "30"})}
	"CIS 5.3.6: sudo timestamp_timeout is 30 minutes, should be 15 or less" in sudo.violations with input as test_input
}

# CIS 5.3.6 — timestamp_timeout not configured at all
test_5_3_6_timeout_not_configured if {
	test_input := {"sudo": object.remove(compliant_sudo, {"timestamp_timeout"})}
	"CIS 5.3.6: sudo timestamp_timeout not configured" in sudo.violations with input as test_input
}

# CIS 5.3.7 — su command not restricted
test_5_3_7_su_not_restricted if {
	test_input := {"sudo": object.union(compliant_sudo, {"su_restricted": false})}
	"CIS 5.3.7: Access to su command not restricted (pam_wheel.so not configured)" in sudo.violations with input as test_input
}

# CIS 5.3.7 — wheel group has no members
test_5_3_7_wheel_group_empty if {
	test_input := {"sudo": object.union(compliant_sudo, {"wheel_group_members": []})}
	"CIS 5.3.7: wheel group has no members - no users can use su" in sudo.violations with input as test_input
}

# CIS 5.3 — /etc/sudoers wrong file mode
test_5_3_sudoers_wrong_mode if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_mode": "0644"})}
	"CIS 5.3: /etc/sudoers has mode 0644, should be 0440 or 0400" in sudo.violations with input as test_input
}

# CIS 5.3 — /etc/sudoers wrong owner
test_5_3_sudoers_wrong_owner if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_owner": "admin"})}
	"CIS 5.3: /etc/sudoers owned by admin, should be root" in sudo.violations with input as test_input
}

# CIS 5.3 — /etc/sudoers wrong group
test_5_3_sudoers_wrong_group if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_group": "wheel"})}
	"CIS 5.3: /etc/sudoers group is wheel, should be root" in sudo.violations with input as test_input
}

# CIS 5.3 — sudoers.d includedir missing
test_5_3_includedir_missing if {
	test_input := {"sudo": object.union(compliant_sudo, {"sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log"})}
	"CIS 5.3: sudoers should include /etc/sudoers.d directory" in sudo.violations with input as test_input
}

# Compliant input produces no violations.
test_compliant_input_has_no_violations if {
	count(sudo.violations) == 0 with input as {"sudo": compliant_sudo}
}

# Contract test (adapted): this module has no compliance_report object, so we
# assert the aggregate `violations` set is a populated set on empty input `{}`
# rather than collapsing to undefined/empty.
test_violations_populated_on_empty_input if {
	result := sudo.violations with input as {}
	is_set(result)
	count(result) > 0
}
