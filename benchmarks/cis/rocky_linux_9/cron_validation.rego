# METADATA
# title: "DERIVED from CIS Rocky Linux 8 Benchmark v3.0.0 — applied to Rocky Linux 9 (provenance: see README) - Section 5.1: Configure time-based..."
# custom:
#   class: security
#   framework: cis_rocky_linux_9
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
package cis_rocky_linux_9.cron

# DERIVED from CIS Rocky Linux 8 Benchmark v3.0.0 — applied to Rocky Linux 9 (provenance: see README) - Section 5.1: Configure time-based job schedulers

import rego.v1

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

default compliant := false

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

# CIS 5.1.2 - 5.1.7: permissions and ownership of the cron files and directories.
# Missing facts fail closed: an unreported mode/owner/group is a violation, not a pass.
cron_paths := {
	"crontab": {"ctl": "5.1.2", "path": "/etc/crontab", "max": "0600", "group": true},
	"cron_hourly": {"ctl": "5.1.3", "path": "/etc/cron.hourly", "max": "0700", "group": false},
	"cron_daily": {"ctl": "5.1.4", "path": "/etc/cron.daily", "max": "0700", "group": false},
	"cron_weekly": {"ctl": "5.1.5", "path": "/etc/cron.weekly", "max": "0700", "group": false},
	"cron_monthly": {"ctl": "5.1.6", "path": "/etc/cron.monthly", "max": "0700", "group": false},
	"cron_d": {"ctl": "5.1.7", "path": "/etc/cron.d", "max": "0700", "group": false},
}

cron_facts := object.get(input, "cron", {})

violations contains msg if {
	some key, spec in cron_paths
	mode := object.get(cron_facts, concat("", [key, "_mode"]), "<not collected>")
	not mode_within(mode, spec.max)
	msg := sprintf("CIS %s: %s has mode %v, should be %s", [spec.ctl, spec.path, mode, spec.max])
}

violations contains msg if {
	some key, spec in cron_paths
	owner := object.get(cron_facts, concat("", [key, "_owner"]), "<not collected>")
	owner != "root"
	msg := sprintf("CIS %s: %s owned by %v, should be root", [spec.ctl, spec.path, owner])
}

violations contains msg if {
	some key, spec in cron_paths
	spec.group
	group := object.get(cron_facts, concat("", [key, "_group"]), "<not collected>")
	group != "root"
	msg := sprintf("CIS %s: %s group is %v, should be root", [spec.ctl, spec.path, group])
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
	mode := object.get(cron_facts, "cron_allow_mode", "<not collected>")
	not mode_within(mode, "0600")
	msg := sprintf("CIS 5.1.8: /etc/cron.allow has mode %v, should be 0600", [mode])
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
	mode := object.get(cron_facts, "at_allow_mode", "<not collected>")
	not mode_within(mode, "0600")
	msg := sprintf("CIS 5.1.9: /etc/at.allow has mode %v, should be 0600", [mode])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 9,
	"section": "5.1 Configure time-based job schedulers",
	"benchmark": "DERIVED from CIS Rocky Linux 8 Benchmark v3.0.0 (applied to Rocky Linux 9)",
}
