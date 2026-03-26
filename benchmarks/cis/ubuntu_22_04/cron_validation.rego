package cis_ubuntu_22_04.cron

# CIS Ubuntu 22.04 LTS Benchmark v1.0.0 - Section 5.1: Configure time-based job schedulers

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

# CIS 5.1.2: Ensure permissions on /etc/crontab are configured
violations contains msg if {
	input.cron.crontab_mode
	input.cron.crontab_mode != "0600"
	msg := sprintf("CIS 5.1.2: /etc/crontab has mode %s, should be 0600", [input.cron.crontab_mode])
}

violations contains msg if {
	input.cron.crontab_owner
	input.cron.crontab_owner != "root"
	msg := sprintf("CIS 5.1.2: /etc/crontab owned by %s, should be root", [input.cron.crontab_owner])
}

violations contains msg if {
	input.cron.crontab_group
	input.cron.crontab_group != "root"
	msg := sprintf("CIS 5.1.2: /etc/crontab group is %s, should be root", [input.cron.crontab_group])
}

# CIS 5.1.3: Ensure permissions on /etc/cron.hourly are configured
violations contains msg if {
	input.cron.cron_hourly_mode
	input.cron.cron_hourly_mode != "0700"
	msg := sprintf("CIS 5.1.3: /etc/cron.hourly has mode %s, should be 0700", [input.cron.cron_hourly_mode])
}

violations contains msg if {
	input.cron.cron_hourly_owner != "root"
	msg := sprintf("CIS 5.1.3: /etc/cron.hourly owned by %s, should be root", [input.cron.cron_hourly_owner])
}

# CIS 5.1.4: Ensure permissions on /etc/cron.daily are configured
violations contains msg if {
	input.cron.cron_daily_mode
	input.cron.cron_daily_mode != "0700"
	msg := sprintf("CIS 5.1.4: /etc/cron.daily has mode %s, should be 0700", [input.cron.cron_daily_mode])
}

violations contains msg if {
	input.cron.cron_daily_owner != "root"
	msg := sprintf("CIS 5.1.4: /etc/cron.daily owned by %s, should be root", [input.cron.cron_daily_owner])
}

# CIS 5.1.5: Ensure permissions on /etc/cron.weekly are configured
violations contains msg if {
	input.cron.cron_weekly_mode
	input.cron.cron_weekly_mode != "0700"
	msg := sprintf("CIS 5.1.5: /etc/cron.weekly has mode %s, should be 0700", [input.cron.cron_weekly_mode])
}

violations contains msg if {
	input.cron.cron_weekly_owner != "root"
	msg := sprintf("CIS 5.1.5: /etc/cron.weekly owned by %s, should be root", [input.cron.cron_weekly_owner])
}

# CIS 5.1.6: Ensure permissions on /etc/cron.monthly are configured
violations contains msg if {
	input.cron.cron_monthly_mode
	input.cron.cron_monthly_mode != "0700"
	msg := sprintf("CIS 5.1.6: /etc/cron.monthly has mode %s, should be 0700", [input.cron.cron_monthly_mode])
}

violations contains msg if {
	input.cron.cron_monthly_owner != "root"
	msg := sprintf("CIS 5.1.6: /etc/cron.monthly owned by %s, should be root", [input.cron.cron_monthly_owner])
}

# CIS 5.1.7: Ensure permissions on /etc/cron.d are configured
violations contains msg if {
	input.cron.cron_d_mode
	input.cron.cron_d_mode != "0700"
	msg := sprintf("CIS 5.1.7: /etc/cron.d has mode %s, should be 0700", [input.cron.cron_d_mode])
}

violations contains msg if {
	input.cron.cron_d_owner != "root"
	msg := sprintf("CIS 5.1.7: /etc/cron.d owned by %s, should be root", [input.cron.cron_d_owner])
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
	input.cron.cron_allow_mode != "0600"
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
	input.cron.at_allow_mode != "0600"
	msg := sprintf("CIS 5.1.9: /etc/at.allow has mode %s, should be 0600", [input.cron.at_allow_mode])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 9,
	"section": "5.1 Configure time-based job schedulers",
	"benchmark": "CIS Ubuntu 22.04 v1.0.0",
}
