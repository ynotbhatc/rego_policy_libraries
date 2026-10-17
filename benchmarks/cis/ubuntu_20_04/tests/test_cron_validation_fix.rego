package cis_ubuntu_20_04.cron_test

import rego.v1

# Validation fix pass 2026-10-17.

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

test_good_input_compliant if {
	data.cis_ubuntu_20_04.cron.compliant with input as good
}

test_missing_mode_owner_evidence_not_compliant if {
	not data.cis_ubuntu_20_04.cron.compliant with input as {"cron": {"crond_enabled": true, "crond_running": true, "cron_allow_exists": true, "at_allow_exists": true}}
}

test_missing_crontab_group_flagged if {
	inp := json.remove(good, ["cron/crontab_group"])
	some msg in data.cis_ubuntu_20_04.cron.violations with input as inp
	contains(msg, "evidence missing")
	contains(msg, "crontab_group")
}

test_more_restrictive_modes_accepted if {
	inp := object.union(good, {"cron": {"crontab_mode": "400", "cron_d_mode": "0500", "cron_allow_mode": "0o400"}})
	data.cis_ubuntu_20_04.cron.compliant with input as inp
}

test_permissive_crond_mode_flagged if {
	inp := object.union(good, {"cron": {"cron_d_mode": "0755"}})
	some msg in data.cis_ubuntu_20_04.cron.violations with input as inp
	startswith(msg, "CIS 5.1.7")
}

test_cron_allow_missing_mode_flagged if {
	inp := json.remove(good, ["cron/cron_allow_mode"])
	not data.cis_ubuntu_20_04.cron.compliant with input as inp
}
