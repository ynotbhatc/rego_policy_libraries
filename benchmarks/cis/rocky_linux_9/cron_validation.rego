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
#     as_of: v2.4.2
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
cron_facts := object.get(input, "cron", {})

# CIS 5.1.2: /etc/crontab
violations contains msg if {
	mode := object.get(cron_facts, "crontab_mode", "<not collected>")
	not mode_within(mode, "0600")
	msg := sprintf("CIS 5.1.2: /etc/crontab has mode %v, should be 0600", [mode])
}

violations contains msg if {
	owner := object.get(cron_facts, "crontab_owner", "<not collected>")
	owner != "root"
	msg := sprintf("CIS 5.1.2: /etc/crontab owned by %v, should be root", [owner])
}

violations contains msg if {
	group := object.get(cron_facts, "crontab_group", "<not collected>")
	group != "root"
	msg := sprintf("CIS 5.1.2: /etc/crontab group is %v, should be root", [group])
}

# CIS 5.1.3: /etc/cron.hourly
violations contains msg if {
	mode := object.get(cron_facts, "cron_hourly_mode", "<not collected>")
	not mode_within(mode, "0700")
	msg := sprintf("CIS 5.1.3: /etc/cron.hourly has mode %v, should be 0700", [mode])
}

violations contains msg if {
	owner := object.get(cron_facts, "cron_hourly_owner", "<not collected>")
	owner != "root"
	msg := sprintf("CIS 5.1.3: /etc/cron.hourly owned by %v, should be root", [owner])
}

# CIS 5.1.4: /etc/cron.daily
violations contains msg if {
	mode := object.get(cron_facts, "cron_daily_mode", "<not collected>")
	not mode_within(mode, "0700")
	msg := sprintf("CIS 5.1.4: /etc/cron.daily has mode %v, should be 0700", [mode])
}

violations contains msg if {
	owner := object.get(cron_facts, "cron_daily_owner", "<not collected>")
	owner != "root"
	msg := sprintf("CIS 5.1.4: /etc/cron.daily owned by %v, should be root", [owner])
}

# CIS 5.1.5: /etc/cron.weekly
violations contains msg if {
	mode := object.get(cron_facts, "cron_weekly_mode", "<not collected>")
	not mode_within(mode, "0700")
	msg := sprintf("CIS 5.1.5: /etc/cron.weekly has mode %v, should be 0700", [mode])
}

violations contains msg if {
	owner := object.get(cron_facts, "cron_weekly_owner", "<not collected>")
	owner != "root"
	msg := sprintf("CIS 5.1.5: /etc/cron.weekly owned by %v, should be root", [owner])
}

# CIS 5.1.6: /etc/cron.monthly
violations contains msg if {
	mode := object.get(cron_facts, "cron_monthly_mode", "<not collected>")
	not mode_within(mode, "0700")
	msg := sprintf("CIS 5.1.6: /etc/cron.monthly has mode %v, should be 0700", [mode])
}

violations contains msg if {
	owner := object.get(cron_facts, "cron_monthly_owner", "<not collected>")
	owner != "root"
	msg := sprintf("CIS 5.1.6: /etc/cron.monthly owned by %v, should be root", [owner])
}

# CIS 5.1.7: /etc/cron.d
violations contains msg if {
	mode := object.get(cron_facts, "cron_d_mode", "<not collected>")
	not mode_within(mode, "0700")
	msg := sprintf("CIS 5.1.7: /etc/cron.d has mode %v, should be 0700", [mode])
}

violations contains msg if {
	owner := object.get(cron_facts, "cron_d_owner", "<not collected>")
	owner != "root"
	msg := sprintf("CIS 5.1.7: /etc/cron.d owned by %v, should be root", [owner])
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
