# METADATA
# title: "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Section 5.1: Configure..."
# custom:
#   class: security
#   framework: cis_debian_11
#   source: cis
#   domains: [linux, debian]
#   coverage:
#     checks: 21
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.1
package cis_debian_11.cron

# DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Section 5.1: Configure time-based job schedulers

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

has_key(obj, k) if {
	_ = obj[k]
}

# [CIS id, path, input key prefix, max mode, checks group too]
path_checks := [
	["5.1.2", "/etc/crontab", "crontab", "0600", true],
	["5.1.3", "/etc/cron.hourly", "cron_hourly", "0700", false],
	["5.1.4", "/etc/cron.daily", "cron_daily", "0700", false],
	["5.1.5", "/etc/cron.weekly", "cron_weekly", "0700", false],
	["5.1.6", "/etc/cron.monthly", "cron_monthly", "0700", false],
	["5.1.7", "/etc/cron.d", "cron_d", "0700", false],
]

# Missing evidence fails closed
violations contains msg if {
	some c in path_checks
	some suffix in ["mode", "owner"]
	not has_key(object.get(input, "cron", {}), sprintf("%s_%s", [c[2], suffix]))
	msg := sprintf("CIS %s: evidence missing — cron.%s_%s not collected", [c[0], c[2], suffix])
}

violations contains msg if {
	some c in path_checks
	c[4]
	not has_key(object.get(input, "cron", {}), sprintf("%s_group", [c[2]]))
	msg := sprintf("CIS %s: evidence missing — cron.%s_group not collected", [c[0], c[2]])
}

violations contains msg if {
	some c in path_checks
	mode := input.cron[sprintf("%s_mode", [c[2]])]
	not mode_within(mode, c[3])
	msg := sprintf("CIS %s: %s has mode %s, should be %s", [c[0], c[1], mode, c[3]])
}

violations contains msg if {
	some c in path_checks
	owner := input.cron[sprintf("%s_owner", [c[2]])]
	owner != "root"
	msg := sprintf("CIS %s: %s owned by %s, should be root", [c[0], c[1], owner])
}

violations contains msg if {
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
	not has_key(input.cron, "cron_allow_mode")
	msg := "CIS 5.1.8: evidence missing — cron.cron_allow_mode not collected"
}

violations contains msg if {
	input.cron.cron_allow_exists
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
	not has_key(input.cron, "at_allow_mode")
	msg := "CIS 5.1.9: evidence missing — cron.at_allow_mode not collected"
}

violations contains msg if {
	input.cron.at_allow_exists
	not mode_within(input.cron.at_allow_mode, "0600")
	msg := sprintf("CIS 5.1.9: /etc/at.allow has mode %s, should be 0600", [input.cron.at_allow_mode])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 9,
	"section": "5.1 Configure time-based job schedulers",
	"benchmark": "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 (applied to Debian 11)",
}
