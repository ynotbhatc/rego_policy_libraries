# METADATA
# title: "DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (see README) - Section 5.3: Configure Sudo"
# custom:
#   class: security
#   framework: cis_ubuntu_24_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 11
#     cited: 8
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.1
package cis_ubuntu_24_04.sudo

# DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (see README) - Section 5.3: Configure Sudo

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# Evidence gates: values and offender lists this module judges must be collected.
violations contains msg if {
	some key in ["nopasswd_entries", "noauthenticate_entries", "timestamp_timeout", "sudoers_mode"]
	object.get(object.get(input, "sudo", {}), key, null) == null
	msg := sprintf("CIS 5.3: evidence missing — sudo.%s not collected", [key])
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
	input.sudo.sudoers_mode
	not mode_within(input.sudo.sudoers_mode, "0440")
	msg := sprintf("CIS 5.3.8: /etc/sudoers has mode %s, should be 0440", [input.sudo.sudoers_mode])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 8,
	"section": "5.3 Configure Sudo",
	"benchmark": "DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 (applied to Ubuntu 24.04 LTS)",
}

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(d) | some d in split(p, "")]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0
