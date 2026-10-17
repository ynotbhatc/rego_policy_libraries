# METADATA
# title: "CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Section 5.1: Configure time-based job schedulers"
# custom:
#   class: security
#   framework: cis_ubuntu_22_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 21
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.1
package cis_ubuntu_22_04.cron

# CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Section 5.1: Configure time-based job schedulers

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# CIS 5.1.1: Ensure cron daemon is enabled and running
violations contains msg if {
	not input.cron.crond_enabled
	msg := "CIS 5.1.1: cron daemon (cron) is not enabled"
}

violations contains msg if {
	input.cron.crond_enabled
	not input.cron.crond_running
	msg := "CIS 5.1.1: cron daemon (cron) is not running"
}

# CIS 5.1.2 - 5.1.7: ownership and mode of the cron files and directories.
# Every mode/owner must be collected: an absent field is a violation, not a pass.
# Modes are octal: a mode passes when it grants nothing beyond `max`.
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

cron_paths := {
	"crontab": {"control": "5.1.2", "path": "/etc/crontab", "max": "0600", "max_label": "0600"},
	"cron_hourly": {"control": "5.1.3", "path": "/etc/cron.hourly", "max": "0700", "max_label": "0700"},
	"cron_daily": {"control": "5.1.4", "path": "/etc/cron.daily", "max": "0700", "max_label": "0700"},
	"cron_weekly": {"control": "5.1.5", "path": "/etc/cron.weekly", "max": "0700", "max_label": "0700"},
	"cron_monthly": {"control": "5.1.6", "path": "/etc/cron.monthly", "max": "0700", "max_label": "0700"},
	"cron_d": {"control": "5.1.7", "path": "/etc/cron.d", "max": "0700", "max_label": "0700"},
}

violations contains msg if {
	some key, p in cron_paths
	not input.cron[sprintf("%s_mode", [key])]
	msg := sprintf("CIS %s: evidence missing — cron.%s_mode not collected", [p.control, key])
}

violations contains msg if {
	some key, p in cron_paths
	mode := input.cron[sprintf("%s_mode", [key])]
	not mode_within(mode, p.max)
	msg := sprintf("CIS %s: %s has mode %s, should be %s", [p.control, p.path, mode, p.max_label])
}

violations contains msg if {
	some key, p in cron_paths
	not input.cron[sprintf("%s_owner", [key])]
	msg := sprintf("CIS %s: evidence missing — cron.%s_owner not collected", [p.control, key])
}

violations contains msg if {
	some key, p in cron_paths
	owner := input.cron[sprintf("%s_owner", [key])]
	owner != "root"
	msg := sprintf("CIS %s: %s owned by %s, should be root", [p.control, p.path, owner])
}

violations contains "CIS 5.1.2: evidence missing — cron.crontab_group not collected" if {
	not input.cron.crontab_group
}

violations contains msg if {
	input.cron.crontab_group
	input.cron.crontab_group != "root"
	msg := sprintf("CIS 5.1.2: /etc/crontab group is %s, should be root", [input.cron.crontab_group])
}

# an allow-file mode must be present and no more permissive than 0600
allow_mode_ok(key) if mode_within(input.cron[key], "0600")

# CIS 5.1.8: Ensure cron is restricted to authorized users
violations contains msg if {
	input.cron.cron_deny_exists
	msg := "CIS 5.1.8: /etc/cron.deny exists - should be removed"
}

violations contains msg if {
	not input.cron.cron_allow_exists
	msg := "CIS 5.1.8: /etc/cron.allow does not exist - should be created"
}

violations contains msg if {
	input.cron.cron_allow_exists
	not allow_mode_ok("cron_allow_mode")
	msg := sprintf("CIS 5.1.8: /etc/cron.allow has mode %v, should be 0600 (or mode not collected)", [object.get(input, ["cron", "cron_allow_mode"], "<missing>")])
}

# CIS 5.1.9: Ensure at is restricted to authorized users
violations contains msg if {
	input.cron.at_deny_exists
	msg := "CIS 5.1.9: /etc/at.deny exists - should be removed"
}

violations contains msg if {
	not input.cron.at_allow_exists
	msg := "CIS 5.1.9: /etc/at.allow does not exist - should be created"
}

violations contains msg if {
	input.cron.at_allow_exists
	not allow_mode_ok("at_allow_mode")
	msg := sprintf("CIS 5.1.9: /etc/at.allow has mode %v, should be 0600 (or mode not collected)", [object.get(input, ["cron", "at_allow_mode"], "<missing>")])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 9,
	"section": "5.1 Configure time-based job schedulers",
	"benchmark": "CIS Ubuntu 22.04 v3.0.0",
}
