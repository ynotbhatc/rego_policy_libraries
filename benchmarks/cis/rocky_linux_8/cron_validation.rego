# METADATA
# title: "CIS Rocky Linux 8 Benchmark v3.0.0 - Section 5.1: Configure time-based job schedulers"
# custom:
#   class: security
#   framework: cis_rocky_linux_8
#   source: cis
#   domains: [linux, rocky]
#   coverage:
#     checks: 21
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.1
package cis_rocky_linux_8.cron

# CIS Rocky Linux 8 Benchmark v3.0.0 - Section 5.1: Configure time-based job schedulers

import rego.v1

default compliant := false

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

compliant if {
	count(violations) == 0
}

# CIS 5.1.1: Ensure cron daemon is enabled and running
violations contains msg if {
	not input.cron.crond_enabled
	msg := "CIS 5.1.1: cron daemon (crond) is not enabled"
}

violations contains msg if {
	input.cron.crond_enabled
	not input.cron.crond_running
	msg := "CIS 5.1.1: cron daemon (crond) is not running"
}

# CIS 5.1.2: Ensure permissions on /etc/crontab are configured
violations contains msg if {
    not input.cron.crontab_mode
    msg := "CIS 5.1.2: evidence missing - cron.crontab_mode not collected"
}

violations contains msg if {
    mode := input.cron.crontab_mode
    not mode_within(mode, "0600")
    msg := sprintf("CIS 5.1.2: /etc/crontab has mode %s, should be 0600 or stricter", [mode])
}

violations contains msg if {
    not input.cron.crontab_owner
    msg := "CIS 5.1.2: evidence missing - cron.crontab_owner not collected"
}

violations contains msg if {
    input.cron.crontab_owner != "root"
    msg := sprintf("CIS 5.1.2: /etc/crontab owned by %s, should be root", [input.cron.crontab_owner])
}

violations contains msg if {
    not input.cron.crontab_group
    msg := "CIS 5.1.2: evidence missing - cron.crontab_group not collected"
}

violations contains msg if {
    input.cron.crontab_group != "root"
    msg := sprintf("CIS 5.1.2: /etc/crontab group is %s, should be root", [input.cron.crontab_group])
}

# CIS 5.1.3 - 5.1.7: cron.hourly/daily/weekly/monthly/d directories (mode 0700 or stricter, owner root)
cron_dirs := {
    "cron_hourly": {"cis": "5.1.3", "path": "/etc/cron.hourly"},
    "cron_daily": {"cis": "5.1.4", "path": "/etc/cron.daily"},
    "cron_weekly": {"cis": "5.1.5", "path": "/etc/cron.weekly"},
    "cron_monthly": {"cis": "5.1.6", "path": "/etc/cron.monthly"},
    "cron_d": {"cis": "5.1.7", "path": "/etc/cron.d"},
}

violations contains msg if {
    some key, d in cron_dirs
    not input.cron[sprintf("%s_mode", [key])]
    msg := sprintf("CIS %s: evidence missing - cron.%s_mode not collected", [d.cis, key])
}

violations contains msg if {
    some key, d in cron_dirs
    mode := input.cron[sprintf("%s_mode", [key])]
    not mode_within(mode, "0700")
    msg := sprintf("CIS %s: %s has mode %s, should be 0700 or stricter", [d.cis, d.path, mode])
}

violations contains msg if {
    some key, d in cron_dirs
    not input.cron[sprintf("%s_owner", [key])]
    msg := sprintf("CIS %s: evidence missing - cron.%s_owner not collected", [d.cis, key])
}

violations contains msg if {
    some key, d in cron_dirs
    owner := input.cron[sprintf("%s_owner", [key])]
    owner != "root"
    msg := sprintf("CIS %s: %s owned by %s, should be root", [d.cis, d.path, owner])
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
    msg := "CIS 5.1.8: evidence missing - cron.cron_allow_mode not collected"
}

violations contains msg if {
    input.cron.cron_allow_exists
    mode := input.cron.cron_allow_mode
    not mode_within(mode, "0600")
    msg := sprintf("CIS 5.1.8: /etc/cron.allow has mode %s, should be 0600 or stricter", [mode])
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
    msg := "CIS 5.1.9: evidence missing - cron.at_allow_mode not collected"
}

violations contains msg if {
    input.cron.at_allow_exists
    mode := input.cron.at_allow_mode
    not mode_within(mode, "0600")
    msg := sprintf("CIS 5.1.9: /etc/at.allow has mode %s, should be 0600 or stricter", [mode])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 9,
	"section": "5.1 Configure time-based job schedulers",
	"benchmark": "CIS Rocky Linux 8 v3.0.0",
}
