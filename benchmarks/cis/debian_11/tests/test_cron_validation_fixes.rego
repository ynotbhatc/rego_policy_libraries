package cis_debian_11.cron_test

import rego.v1

good := {"cron": {
	"crond_enabled": true, "crond_running": true,
	"crontab_mode": "0600", "crontab_owner": "root", "crontab_group": "root",
	"cron_hourly_mode": "0700", "cron_hourly_owner": "root",
	"cron_daily_mode": "0700", "cron_daily_owner": "root",
	"cron_weekly_mode": "0700", "cron_weekly_owner": "root",
	"cron_monthly_mode": "0700", "cron_monthly_owner": "root",
	"cron_d_mode": "0700", "cron_d_owner": "root",
	"cron_deny_exists": false, "cron_allow_exists": true, "cron_allow_mode": "0600",
	"at_deny_exists": false, "at_allow_exists": true, "at_allow_mode": "0600",
}}

test_good_compliant if {
	data.cis_debian_11.cron.compliant with input as good
}

test_missing_crontab_mode_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/cron/crontab_mode"}])
	some m in data.cis_debian_11.cron.violations with input as i
	contains(m, "evidence missing")
}

test_missing_cron_d_owner_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/cron/cron_d_owner"}])
	some m in data.cis_debian_11.cron.violations with input as i
	contains(m, "cron_d_owner")
}

test_missing_hourly_owner_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/cron/cron_hourly_owner"}])
	not data.cis_debian_11.cron.compliant with input as i
}

test_missing_allow_mode_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/cron/cron_allow_mode"}])
	not data.cis_debian_11.cron.compliant with input as i
}

test_stricter_dir_mode_ok if {
	i := json.patch(good, [{"op": "replace", "path": "/cron/cron_daily_mode", "value": "700"}])
	data.cis_debian_11.cron.compliant with input as i
}

test_loose_mode_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/cron/crontab_mode", "value": "0644"}])
	not data.cis_debian_11.cron.compliant with input as i
}
