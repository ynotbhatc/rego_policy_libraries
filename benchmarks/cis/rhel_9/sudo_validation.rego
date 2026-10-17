# METADATA
# title: "CIS Section 5.3: Configure privilege escalation (sudo)"
# custom:
#   class: security
#   framework: cis_rhel_9
#   source: cis
#   domains: [linux, rhel]
#   coverage:
#     checks: 14
#     cited: 8
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.1
package cis_rhel9.sudo

import rego.v1

# CIS Section 5.3: Configure privilege escalation (sudo)
# Sudo configuration validation

default compliant := false

# Helper to check if sudo is installed
sudo_installed if {
    input.sudo.installed
}

# Helper to parse sudoers file
sudoers_has_option(option) if {
    some line in split(input.sudo.sudoers_content, "\n")
    trimmed := trim_space(line)
    not startswith(trimmed, "#")
    contains(trimmed, option)
}

violations contains msg if {
    not sudo_installed
    msg := "CIS 5.3.1: sudo package not installed"
}

# CIS 5.3.2: Ensure sudo commands use pty
violations contains msg if {
    sudo_installed
    not sudoers_has_option("use_pty")
    msg := "CIS 5.3.2: sudo not configured to use pty (Defaults use_pty missing)"
}

# CIS 5.3.3: Ensure sudo log file exists
violations contains msg if {
    sudo_installed
    not sudoers_has_option("logfile=")
    msg := "CIS 5.3.3: sudo logfile not configured (Defaults logfile= missing)"
}

violations contains msg if {
    sudo_installed
    sudoers_has_option("logfile=")
    not input.sudo.logfile_exists
    msg := "CIS 5.3.3: sudo logfile configured but file does not exist"
}

# CIS 5.3.4: Ensure users must provide password for privilege escalation
violations contains msg if {
    sudo_installed
    sudoers_has_option("NOPASSWD:")
    msg := "CIS 5.3.4: NOPASSWD option found in sudoers - users should provide password"
}

# CIS 5.3.5: Ensure re-authentication for privilege escalation is not disabled globally
violations contains msg if {
    sudo_installed
    sudoers_has_option("!authenticate")
    msg := "CIS 5.3.5: !authenticate found in sudoers - re-authentication is disabled"
}

# CIS 5.3.6: Ensure sudo authentication timeout is configured correctly
violations contains msg if {
    sudo_installed
    input.sudo.timestamp_timeout
    to_number(input.sudo.timestamp_timeout) > 15
    msg := sprintf("CIS 5.3.6: sudo timestamp_timeout is %s minutes, should be 15 or less", [input.sudo.timestamp_timeout])
}

violations contains msg if {
    sudo_installed
    not input.sudo.timestamp_timeout
    not sudoers_has_option("timestamp_timeout=")
    msg := "CIS 5.3.6: sudo timestamp_timeout not configured"
}

# CIS 5.3.7: Ensure access to the su command is restricted
violations contains msg if {
    not input.sudo.su_restricted
    msg := "CIS 5.3.7: Access to su command not restricted (pam_wheel.so not configured)"
}

violations contains msg if {
    input.sudo.su_restricted
    count(input.sudo.wheel_group_members) == 0
    msg := "CIS 5.3.7: wheel group has no members - no users can use su"
}

# Additional checks for sudoers file permissions
violations contains msg if {
    input.sudo.installed
    not input.sudo.sudoers_mode
    msg := "CIS 5.3: evidence missing — sudo.sudoers_mode not collected"
}

violations contains msg if {
    input.sudo.sudoers_mode
    not mode_within(input.sudo.sudoers_mode, "0440")
    msg := sprintf("CIS 5.3: /etc/sudoers has mode %s, should be 0440 or 0400", [input.sudo.sudoers_mode])
}

violations contains msg if {
    input.sudo.sudoers_owner
    input.sudo.sudoers_owner != "root"
    msg := sprintf("CIS 5.3: /etc/sudoers owned by %s, should be root", [input.sudo.sudoers_owner])
}

violations contains msg if {
    input.sudo.sudoers_group
    input.sudo.sudoers_group != "root"
    msg := sprintf("CIS 5.3: /etc/sudoers group is %s, should be root", [input.sudo.sudoers_group])
}

# Check for includedir in sudoers
violations contains msg if {
    sudo_installed
    not sudoers_has_option("#includedir /etc/sudoers.d")
    not sudoers_has_option("@includedir /etc/sudoers.d")
    msg := "CIS 5.3: sudoers should include /etc/sudoers.d directory"
}

# Compliance check
compliant if {
    count(violations) == 0
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
