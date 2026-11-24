# METADATA
# title: "CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 5.3: Configure Sudo"
# custom:
#   class: security
#   framework: cis_ubuntu_20_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 15
#     cited: 8
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package cis_ubuntu_20_04.sudo

# CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 5.3: Configure Sudo

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# CIS 5.3.1: sudo must be present
violations contains msg if {
	input.sudo.installed == false
	msg := "CIS 5.3.1: sudo is not installed"
}

# CIS 5.3.2: sudo commands must allocate a pseudo-terminal
violations contains msg if {
	input.sudo.use_pty == false
	msg := "CIS 5.3.2: sudo is not configured to use pty (Defaults use_pty not found)"
}

# CIS 5.3.3: a log file for sudo must exist
violations contains msg if {
	input.sudo.logfile_configured == false
	msg := "CIS 5.3.3: sudo log file is not configured (Defaults logfile not found)"
}

# CIS 5.3.4: checked condition — users must provide password for privilege escalation
violations contains msg if {
	some line in input.sudo.nopasswd_entries
	not startswith(line, "#")
	msg := sprintf("CIS 5.3.4: NOPASSWD found in sudoers: %s", [line])
}

# CIS 5.3.5: re-authentication for privilege escalation must stay in effect globally
violations contains msg if {
	some line in input.sudo.noauthenticate_entries
	not startswith(line, "#")
	msg := sprintf("CIS 5.3.5: !authenticate found in sudoers: %s", [line])
}

# CIS 5.3.6: sudo authentication timeout must match the approved configuration
violations contains msg if {
	is_number(input.sudo.timestamp_timeout)
	input.sudo.timestamp_timeout > 15
	msg := sprintf("CIS 5.3.6: sudo timestamp_timeout is %d minutes, should be 15 or less", [input.sudo.timestamp_timeout])
}

violations contains msg if {
	is_number(input.sudo.timestamp_timeout)
	input.sudo.timestamp_timeout < 0
	msg := "CIS 5.3.6: sudo timestamp_timeout is negative (0 is recommended for high security)"
}

violations contains msg if {
	not is_number(object.get(input, ["sudo", "timestamp_timeout"], 0))
	msg := "CIS 5.3.6: evidence missing — sudo.timestamp_timeout is not a number"
}

# CIS 5.3.7: access to the su command must be restricted
violations contains msg if {
	input.sudo.su_restricted == false
	msg := "CIS 5.3.7: su command is not restricted (pam_wheel.so not configured)"
}

violations contains msg if {
	input.sudo.su_allowed_group
	input.sudo.su_allowed_group != "sudo"
	input.sudo.su_allowed_group != "wheel"
	msg := sprintf("CIS 5.3.7: su is restricted to group '%s' - verify this is the correct privileged group", [input.sudo.su_allowed_group])
}

# CIS 5.3.8: sudo must be not executable by all users
violations contains msg if {
	input.sudo.sudoers_world_readable == true
	msg := "CIS 5.3.8: /etc/sudoers is world-readable"
}

violations contains msg if {
	not mode_within(input.sudo.sudoers_mode, "0440")
	msg := sprintf("CIS 5.3.8: /etc/sudoers has mode %s, should be 0440 or more restrictive", [input.sudo.sudoers_mode])
}

violations contains msg if {
	not input.sudo.sudoers_mode
	msg := "CIS 5.3.8: evidence missing — sudo.sudoers_mode not collected"
}

# ---------------------------------------------------------------------------
# Evidence rule: a yes/no fact is answered only by a JSON boolean. A missing fact, null, a string
# ("true", "false", "no") or a number is an evidence problem: the control fails and the finding names it.
# ---------------------------------------------------------------------------
flag_problem(path) := "not collected" if is_null(object.get(input, path, null))

flag_problem(path) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(input, path, null)
	not is_null(v)
	not is_boolean(v)
}

flag_evidence(prefix, path) := sprintf("%s: evidence missing — %s %s", [prefix, concat(".", path), flag_problem(path)])

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags := [
	["CIS 5.3.1", ["sudo", "installed"]],
	["CIS 5.3.2", ["sudo", "use_pty"]],
	["CIS 5.3.3", ["sudo", "logfile_configured"]],
	["CIS 5.3.7", ["sudo", "su_restricted"]],
	["CIS 5.3.8", ["sudo", "sudoers_world_readable"]],
]

violations contains msg if {
	some [prefix, path] in required_flags
	msg := flag_evidence(prefix, path)
}

# offender lists: an empty list is an answer ("none found"), a missing list is not
required_lists := {
	"nopasswd_entries": "5.3.4",
	"noauthenticate_entries": "5.3.5",
}

violations contains msg if {
	some key, ctl in required_lists
	not is_array(object.get(input, ["sudo", key], null))
	msg := sprintf("CIS %s: evidence missing — sudo.%s not collected", [ctl, key])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 8,
	"section": "5.3 Configure Sudo",
	"benchmark": "CIS Ubuntu 20.04 v3.0.0",
}
