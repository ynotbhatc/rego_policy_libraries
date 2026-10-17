# METADATA
# title: "DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (see README) - Section 5.1: Configure time-based..."
# custom:
#   class: security
#   framework: cis_ubuntu_24_04
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
package cis_ubuntu_24_04.cron

# DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (see README) - Section 5.1: Configure time-based job schedulers

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

# CIS 5.1.2 - 5.1.7: permissions on /etc/crontab and the cron.* directories.
# Each (cis, path, key prefix, max mode) row requires mode and owner evidence;
# a missing field is a violation (fail closed), stricter modes are accepted.
cron_paths := [
	{"cis": "5.1.2", "path": "/etc/crontab", "key": "crontab", "max": "0600"},
	{"cis": "5.1.3", "path": "/etc/cron.hourly", "key": "cron_hourly", "max": "0700"},
	{"cis": "5.1.4", "path": "/etc/cron.daily", "key": "cron_daily", "max": "0700"},
	{"cis": "5.1.5", "path": "/etc/cron.weekly", "key": "cron_weekly", "max": "0700"},
	{"cis": "5.1.6", "path": "/etc/cron.monthly", "key": "cron_monthly", "max": "0700"},
	{"cis": "5.1.7", "path": "/etc/cron.d", "key": "cron_d", "max": "0700"},
]

violations contains msg if {
	some c in cron_paths
	field := concat("_", [c.key, "mode"])
	not input.cron[field]
	msg := sprintf("CIS %s: evidence missing — %s not collected", [c.cis, field])
}

violations contains msg if {
	some c in cron_paths
	mode := input.cron[concat("_", [c.key, "mode"])]
	not mode_within(mode, c.max)
	msg := sprintf("CIS %s: %s has mode %s, should be %s", [c.cis, c.path, mode, c.max])
}

violations contains msg if {
	some c in cron_paths
	field := concat("_", [c.key, "owner"])
	not input.cron[field]
	msg := sprintf("CIS %s: evidence missing — %s not collected", [c.cis, field])
}

violations contains msg if {
	some c in cron_paths
	owner := input.cron[concat("_", [c.key, "owner"])]
	owner != "root"
	msg := sprintf("CIS %s: %s owned by %s, should be root", [c.cis, c.path, owner])
}

violations contains "CIS 5.1.2: evidence missing — crontab_group not collected" if {
	not input.cron.crontab_group
}

violations contains msg if {
	input.cron.crontab_group
	input.cron.crontab_group != "root"
	msg := sprintf("CIS 5.1.2: /etc/crontab group is %s, should be root", [input.cron.crontab_group])
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
	not input.cron.cron_allow_mode
	msg := "CIS 5.1.8: evidence missing — cron_allow_mode not collected"
}

violations contains msg if {
	input.cron.cron_allow_exists
	input.cron.cron_allow_mode
	not mode_within(input.cron.cron_allow_mode, "0600")
	msg := sprintf("CIS 5.1.8: /etc/cron.allow has mode %s, should be 0600", [input.cron.cron_allow_mode])
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
	not input.cron.at_allow_mode
	msg := "CIS 5.1.9: evidence missing — at_allow_mode not collected"
}

violations contains msg if {
	input.cron.at_allow_exists
	input.cron.at_allow_mode
	not mode_within(input.cron.at_allow_mode, "0600")
	msg := sprintf("CIS 5.1.9: /etc/at.allow has mode %s, should be 0600", [input.cron.at_allow_mode])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 9,
	"section": "5.1 Configure time-based job schedulers",
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
