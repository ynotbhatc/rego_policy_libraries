package cis_rocky_linux_9.sudo_test

import rego.v1

inp(content) := {"sudo": {"installed": true, "sudoers_content": content}}

has(prefix, i) if {
	v := data.cis_rocky_linux_9.sudo.violations with input as i
	some x in v
	startswith(x, prefix)
}

test_negated_use_pty_flagged if has("CIS 5.3.2", inp("Defaults !use_pty\n"))
test_use_pty_ok if not has("CIS 5.3.2", inp("Defaults use_pty\n"))
test_use_pty_in_list_ok if not has("CIS 5.3.2", inp("Defaults env_reset, use_pty\n"))
test_commented_use_pty_flagged if has("CIS 5.3.2", inp("# Defaults use_pty\n"))
test_use_pty_then_negated_flagged if has("CIS 5.3.2", inp("Defaults use_pty\nDefaults !use_pty\n"))
test_scoped_use_pty_flagged if has("CIS 5.3.2", inp("Defaults:alice use_pty\n"))

test_includedir_directive_recognised if not has("CIS 5.3: sudoers should include", inp("Defaults use_pty\n#includedir /etc/sudoers.d\n"))
test_at_includedir_recognised if not has("CIS 5.3: sudoers should include", inp("@includedir /etc/sudoers.d\n"))
test_missing_includedir_flagged if has("CIS 5.3: sudoers should include", inp("Defaults use_pty\n"))
test_other_includedir_flagged if has("CIS 5.3: sudoers should include", inp("#includedir /etc/other.d\n"))

test_logfile_set_ok if not has("CIS 5.3.3: sudo logfile not configured", inp("Defaults logfile=\"/var/log/sudo.log\"\n"))
test_logfile_missing_flagged if has("CIS 5.3.3: sudo logfile not configured", inp("Defaults use_pty\n"))
