package cis_amazon_linux_2023.cron_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

good := {"cron": {
	"crond_enabled": true, "crond_running": true,
	"crontab_mode": "0600", "crontab_owner": "root", "crontab_group": "root",
	"cron_hourly_mode": "0700", "cron_hourly_owner": "root",
	"cron_daily_mode": "0700", "cron_daily_owner": "root",
	"cron_weekly_mode": "0700", "cron_weekly_owner": "root",
	"cron_monthly_mode": "0700", "cron_monthly_owner": "root",
	"cron_d_mode": "0700", "cron_d_owner": "root",
	"cron_allow_exists": true, "cron_allow_mode": "0600",
	"at_allow_exists": true, "at_allow_mode": "0600",
}}

test_cron_good_input_compliant if {
	data.cis_amazon_linux_2023.cron.compliant with input as good
}

test_cron_stricter_modes_allowed if {
	i := object.union(good, {"cron": {"crontab_mode": "0400", "cron_hourly_mode": "0500", "cron_allow_mode": "0400"}})
	data.cis_amazon_linux_2023.cron.compliant with input as i
}

test_cron_permissive_mode_flagged if {
	i := object.union(good, {"cron": {"crontab_mode": "0644"}})
	v := data.cis_amazon_linux_2023.cron.violations with input as i
	count(v) == 1
}

test_cron_missing_owner_facts_not_compliant if {
	i := {"cron": {"crond_enabled": true, "crond_running": true, "crontab_mode": "0600", "cron_allow_exists": true, "cron_allow_mode": "0600", "at_allow_exists": true, "at_allow_mode": "0600"}}
	not data.cis_amazon_linux_2023.cron.compliant with input as i
	v := data.cis_amazon_linux_2023.cron.violations with input as i
	"CIS 5.1.2: evidence missing - cron.crontab_owner not collected" in v
	"CIS 5.1.3: evidence missing - cron.cron_hourly_owner not collected" in v
}

test_cron_allow_file_without_mode_flagged if {
	v := data.cis_amazon_linux_2023.cron.violations with input as {"cron": object.remove(good.cron, ["cron_allow_mode"])}
	"CIS 5.1.8: evidence missing - cron.cron_allow_mode not collected" in v
}
