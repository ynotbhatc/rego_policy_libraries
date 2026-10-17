# METADATA
# title: "CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 5.1: Configure time-based job schedulers"
# custom:
#   class: security
#   framework: cis_ubuntu_20_04
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
package cis_ubuntu_20_04.cron

# CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 5.1: Configure time-based job schedulers

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

# CIS 5.1.2-5.1.7: mode (at most `max`), owner and group of cron paths.
# Missing evidence is a violation, not a pass.
cron_path_checks := [
	{"ctl": "5.1.2", "path": "/etc/crontab", "prefix": "crontab", "max": "0600", "group": true},
	{"ctl": "5.1.3", "path": "/etc/cron.hourly", "prefix": "cron_hourly", "max": "0700", "group": false},
	{"ctl": "5.1.4", "path": "/etc/cron.daily", "prefix": "cron_daily", "max": "0700", "group": false},
	{"ctl": "5.1.5", "path": "/etc/cron.weekly", "prefix": "cron_weekly", "max": "0700", "group": false},
	{"ctl": "5.1.6", "path": "/etc/cron.monthly", "prefix": "cron_monthly", "max": "0700", "group": false},
	{"ctl": "5.1.7", "path": "/etc/cron.d", "prefix": "cron_d", "max": "0700", "group": false},
]

violations contains msg if {
	some c in cron_path_checks
	mode := input.cron[sprintf("%s_mode", [c.prefix])]
	not mode_within(mode, c.max)
	msg := sprintf("CIS %s: %s has mode %s, should be %s", [c.ctl, c.path, mode, c.max])
}

violations contains msg if {
	some c in cron_path_checks
	owner := input.cron[sprintf("%s_owner", [c.prefix])]
	owner != "root"
	msg := sprintf("CIS %s: %s owned by %s, should be root", [c.ctl, c.path, owner])
}

violations contains msg if {
	some c in cron_path_checks
	c.group
	group := input.cron[sprintf("%s_group", [c.prefix])]
	group != "root"
	msg := sprintf("CIS %s: %s group is %s, should be root", [c.ctl, c.path, group])
}

violations contains msg if {
	some c in cron_path_checks
	some field in ["mode", "owner", "group"]
	field != "group"
	not input.cron[sprintf("%s_%s", [c.prefix, field])]
	msg := sprintf("CIS %s: evidence missing — cron.%s_%s not collected", [c.ctl, c.prefix, field])
}

violations contains msg if {
	some c in cron_path_checks
	c.group
	not input.cron[sprintf("%s_group", [c.prefix])]
	msg := sprintf("CIS %s: evidence missing — cron.%s_group not collected", [c.ctl, c.prefix])
}

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
	not mode_within(input.cron.cron_allow_mode, "0600")
	msg := sprintf("CIS 5.1.8: /etc/cron.allow has mode %s, should be 0600", [input.cron.cron_allow_mode])
}

violations contains msg if {
	input.cron.cron_allow_exists
	not input.cron.cron_allow_mode
	msg := "CIS 5.1.8: evidence missing — cron.cron_allow_mode not collected"
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
	not mode_within(input.cron.at_allow_mode, "0600")
	msg := sprintf("CIS 5.1.9: /etc/at.allow has mode %s, should be 0600", [input.cron.at_allow_mode])
}

violations contains msg if {
	input.cron.at_allow_exists
	not input.cron.at_allow_mode
	msg := "CIS 5.1.9: evidence missing — cron.at_allow_mode not collected"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 9,
	"section": "5.1 Configure time-based job schedulers",
	"benchmark": "CIS Ubuntu 20.04 v3.0.0",
}
