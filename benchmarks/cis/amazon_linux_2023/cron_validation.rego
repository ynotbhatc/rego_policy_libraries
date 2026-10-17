# METADATA
# title: "CIS Section 5.1: Configure time-based job schedulers"
# custom:
#   class: security
#   framework: cis_amazon_linux_2023
#   source: cis
#   domains: [linux, amazon-linux]
#   coverage:
#     checks: 36
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_amazon_linux_2023.cron

import rego.v1

# CIS Section 5.1: Configure time-based job schedulers
# Cron and at daemon configuration validation

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
# CIS 5.1.3: /etc/cron.hourly
violations contains msg if {
    not input.cron.cron_hourly_mode
    msg := "CIS 5.1.3: evidence missing - cron.cron_hourly_mode not collected"
}

violations contains msg if {
    mode := input.cron.cron_hourly_mode
    not mode_within(mode, "0700")
    msg := sprintf("CIS 5.1.3: /etc/cron.hourly has mode %s, should be 0700 or stricter", [mode])
}

violations contains msg if {
    not input.cron.cron_hourly_owner
    msg := "CIS 5.1.3: evidence missing - cron.cron_hourly_owner not collected"
}

violations contains msg if {
    owner := input.cron.cron_hourly_owner
    owner != "root"
    msg := sprintf("CIS 5.1.3: /etc/cron.hourly owned by %s, should be root", [owner])
}

# CIS 5.1.4: /etc/cron.daily
violations contains msg if {
    not input.cron.cron_daily_mode
    msg := "CIS 5.1.4: evidence missing - cron.cron_daily_mode not collected"
}

violations contains msg if {
    mode := input.cron.cron_daily_mode
    not mode_within(mode, "0700")
    msg := sprintf("CIS 5.1.4: /etc/cron.daily has mode %s, should be 0700 or stricter", [mode])
}

violations contains msg if {
    not input.cron.cron_daily_owner
    msg := "CIS 5.1.4: evidence missing - cron.cron_daily_owner not collected"
}

violations contains msg if {
    owner := input.cron.cron_daily_owner
    owner != "root"
    msg := sprintf("CIS 5.1.4: /etc/cron.daily owned by %s, should be root", [owner])
}

# CIS 5.1.5: /etc/cron.weekly
violations contains msg if {
    not input.cron.cron_weekly_mode
    msg := "CIS 5.1.5: evidence missing - cron.cron_weekly_mode not collected"
}

violations contains msg if {
    mode := input.cron.cron_weekly_mode
    not mode_within(mode, "0700")
    msg := sprintf("CIS 5.1.5: /etc/cron.weekly has mode %s, should be 0700 or stricter", [mode])
}

violations contains msg if {
    not input.cron.cron_weekly_owner
    msg := "CIS 5.1.5: evidence missing - cron.cron_weekly_owner not collected"
}

violations contains msg if {
    owner := input.cron.cron_weekly_owner
    owner != "root"
    msg := sprintf("CIS 5.1.5: /etc/cron.weekly owned by %s, should be root", [owner])
}

# CIS 5.1.6: /etc/cron.monthly
violations contains msg if {
    not input.cron.cron_monthly_mode
    msg := "CIS 5.1.6: evidence missing - cron.cron_monthly_mode not collected"
}

violations contains msg if {
    mode := input.cron.cron_monthly_mode
    not mode_within(mode, "0700")
    msg := sprintf("CIS 5.1.6: /etc/cron.monthly has mode %s, should be 0700 or stricter", [mode])
}

violations contains msg if {
    not input.cron.cron_monthly_owner
    msg := "CIS 5.1.6: evidence missing - cron.cron_monthly_owner not collected"
}

violations contains msg if {
    owner := input.cron.cron_monthly_owner
    owner != "root"
    msg := sprintf("CIS 5.1.6: /etc/cron.monthly owned by %s, should be root", [owner])
}

# CIS 5.1.7: /etc/cron.d
violations contains msg if {
    not input.cron.cron_d_mode
    msg := "CIS 5.1.7: evidence missing - cron.cron_d_mode not collected"
}

violations contains msg if {
    mode := input.cron.cron_d_mode
    not mode_within(mode, "0700")
    msg := sprintf("CIS 5.1.7: /etc/cron.d has mode %s, should be 0700 or stricter", [mode])
}

violations contains msg if {
    not input.cron.cron_d_owner
    msg := "CIS 5.1.7: evidence missing - cron.cron_d_owner not collected"
}

violations contains msg if {
    owner := input.cron.cron_d_owner
    owner != "root"
    msg := sprintf("CIS 5.1.7: /etc/cron.d owned by %s, should be root", [owner])
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

# Compliance check
compliant if {
    count(violations) == 0
}
