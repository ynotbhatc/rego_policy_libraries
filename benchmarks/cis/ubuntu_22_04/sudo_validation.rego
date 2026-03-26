package cis_ubuntu_22_04.sudo

# CIS Ubuntu 22.04 LTS Benchmark v1.0.0 - Section 5.3: Configure Sudo

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# CIS 5.3.1: Ensure sudo is installed
violations contains msg if {
	not input.sudo.installed
	msg := "CIS 5.3.1: sudo is not installed"
}

# CIS 5.3.2: Ensure sudo commands use pty
violations contains msg if {
	not input.sudo.use_pty
	msg := "CIS 5.3.2: sudo is not configured to use pty (Defaults use_pty not found)"
}

# CIS 5.3.3: Ensure sudo log file exists
violations contains msg if {
	not input.sudo.logfile_configured
	msg := "CIS 5.3.3: sudo log file is not configured (Defaults logfile not found)"
}

# CIS 5.3.4: Ensure users must provide password for privilege escalation
violations contains msg if {
	some line in input.sudo.nopasswd_entries
	not startswith(line, "#")
	msg := sprintf("CIS 5.3.4: NOPASSWD found in sudoers: %s", [line])
}

# CIS 5.3.5: Ensure re-authentication for privilege escalation is not disabled globally
violations contains msg if {
	some line in input.sudo.noauthenticate_entries
	not startswith(line, "#")
	msg := sprintf("CIS 5.3.5: !authenticate found in sudoers: %s", [line])
}

# CIS 5.3.6: Ensure sudo authentication timeout is configured correctly
violations contains msg if {
	input.sudo.timestamp_timeout > 15
	msg := sprintf("CIS 5.3.6: sudo timestamp_timeout is %d minutes, should be 15 or less", [input.sudo.timestamp_timeout])
}

violations contains msg if {
	input.sudo.timestamp_timeout < 0
	msg := "CIS 5.3.6: sudo timestamp_timeout is negative (0 is recommended for high security)"
}

# CIS 5.3.7: Ensure access to the su command is restricted
violations contains msg if {
	not input.sudo.su_restricted
	msg := "CIS 5.3.7: su command is not restricted (pam_wheel.so not configured)"
}

violations contains msg if {
	input.sudo.su_allowed_group
	input.sudo.su_allowed_group != "sudo"
	input.sudo.su_allowed_group != "wheel"
	msg := sprintf("CIS 5.3.7: su is restricted to group '%s' - verify this is the correct privileged group", [input.sudo.su_allowed_group])
}

# CIS 5.3.8: Ensure sudo is not executable by all users
violations contains msg if {
	input.sudo.sudoers_world_readable
	msg := "CIS 5.3.8: /etc/sudoers is world-readable"
}

violations contains msg if {
	input.sudo.sudoers_mode != "0440"
	msg := sprintf("CIS 5.3.8: /etc/sudoers has mode %s, should be 0440", [input.sudo.sudoers_mode])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 8,
	"section": "5.3 Configure Sudo",
	"benchmark": "CIS Ubuntu 22.04 v1.0.0",
}
