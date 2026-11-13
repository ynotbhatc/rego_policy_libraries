package cis_rhel8.sudo_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes (octal mode comparison).

sudoers_mode_violation(mode) if {
	v := data.cis_rhel8.sudo.violations with input as {"sudo": {"installed": true, "sudoers_mode": mode}}
	some x in v
	startswith(x, "CIS 5.3: /etc/sudoers has mode")
}

test_sudoers_mode_0440_and_0400_accepted if {
	every m in ["0440", "0400", "440", "0o440"] {
		not sudoers_mode_violation(m)
	}
}

test_sudoers_mode_stricter_than_0440_accepted if {
	not sudoers_mode_violation("0000")
	not sudoers_mode_violation("0040")
}

test_sudoers_mode_looser_flagged if {
	every m in ["0640", "0444", "0644", "0441"] {
		sudoers_mode_violation(m)
	}
}

# Semantic review 2026-11-13: #includedir is a directive, negated Defaults do not count.
test_includedir_directive_accepted if {
	v := data.cis_rhel8.sudo.violations with input as {"sudo": {"installed": true, "sudoers_content": "Defaults use_pty\n#includedir /etc/sudoers.d\n"}}
	not "CIS 5.3: sudoers should include /etc/sudoers.d directory" in v
}

test_includedir_missing_flagged if {
	v := data.cis_rhel8.sudo.violations with input as {"sudo": {"installed": true, "sudoers_content": "Defaults use_pty\n"}}
	"CIS 5.3: sudoers should include /etc/sudoers.d directory" in v
}

test_negated_use_pty_flagged if {
	v := data.cis_rhel8.sudo.violations with input as {"sudo": {"installed": true, "sudoers_content": "Defaults !use_pty\n"}}
	"CIS 5.3.2: sudo not configured to use pty (Defaults use_pty missing)" in v
}

test_negated_logfile_flagged if {
	v := data.cis_rhel8.sudo.violations with input as {"sudo": {"installed": true, "sudoers_content": "Defaults use_pty\nDefaults !logfile=/var/log/sudo.log\n"}}
	"CIS 5.3.3: sudo logfile not configured (Defaults logfile= missing)" in v
}
