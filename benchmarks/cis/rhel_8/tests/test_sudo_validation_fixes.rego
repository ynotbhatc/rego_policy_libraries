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
