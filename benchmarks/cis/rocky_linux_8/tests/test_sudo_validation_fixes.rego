package cis_rocky_linux_8.sudo_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

has(prefix, v) if {
	some m in v
	startswith(m, prefix)
}

test_sudo_includedir_directive_recognised if {
	i := {"sudo": {"installed": true, "sudoers_content": "Defaults use_pty\n#includedir /etc/sudoers.d\n"}}
	v := data.cis_rocky_linux_8.sudo.violations with input as i
	not has("CIS 5.3: sudoers should include", v)
}

test_sudo_atincludedir_directive_recognised if {
	i := {"sudo": {"installed": true, "sudoers_content": "@includedir /etc/sudoers.d\n"}}
	v := data.cis_rocky_linux_8.sudo.violations with input as i
	not has("CIS 5.3: sudoers should include", v)
}

test_sudo_missing_includedir_flagged if {
	i := {"sudo": {"installed": true, "sudoers_content": "Defaults use_pty\n# includedir /etc/sudoers.d\n"}}
	v := data.cis_rocky_linux_8.sudo.violations with input as i
	has("CIS 5.3: sudoers should include", v)
}

test_sudo_negated_use_pty_flagged if {
	i := {"sudo": {"installed": true, "sudoers_content": "Defaults !use_pty\n"}}
	v := data.cis_rocky_linux_8.sudo.violations with input as i
	has("CIS 5.3.2", v)
}

test_sudo_use_pty_in_list_ok if {
	i := {"sudo": {"installed": true, "sudoers_content": "Defaults env_reset, use_pty\n"}}
	v := data.cis_rocky_linux_8.sudo.violations with input as i
	not has("CIS 5.3.2", v)
}

test_sudo_use_pty_plain_ok if {
	i := {"sudo": {"installed": true, "sudoers_content": "Defaults    use_pty\n"}}
	v := data.cis_rocky_linux_8.sudo.violations with input as i
	not has("CIS 5.3.2", v)
}

test_sudo_timestamp_timeout_never_expires_flagged if {
	v := data.cis_rocky_linux_8.sudo.violations with input as {"sudo": {"installed": true, "timestamp_timeout": "-1"}}
	has("CIS 5.3.6: sudo timestamp_timeout is -1", v)
}

test_sudo_timestamp_timeout_15_ok if {
	v := data.cis_rocky_linux_8.sudo.violations with input as {"sudo": {"installed": true, "timestamp_timeout": "15"}}
	not has("CIS 5.3.6", v)
}
