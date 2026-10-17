package cis_rhel8.cron_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

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

test_cron_fully_evidenced_input_is_compliant if {
	data.cis_rhel8.cron.compliant with input as good
}

test_cron_missing_owner_is_violation if {
	i := json.remove(good, ["cron/cron_hourly_owner"])
	v := data.cis_rhel8.cron.violations with input as i
	"CIS 5.1.3: evidence missing — cron_hourly_owner not collected" in v
	not data.cis_rhel8.cron.compliant with input as i
}

test_cron_missing_mode_is_violation if {
	i := json.remove(good, ["cron/crontab_mode"])
	v := data.cis_rhel8.cron.violations with input as i
	"CIS 5.1.2: evidence missing — crontab_mode not collected" in v
}

test_cron_missing_group_is_violation if {
	i := json.remove(good, ["cron/crontab_group"])
	v := data.cis_rhel8.cron.violations with input as i
	"CIS 5.1.2: evidence missing — crontab_group not collected" in v
}

test_cron_missing_allow_mode_is_violation if {
	i := json.remove(good, ["cron/at_allow_mode"])
	v := data.cis_rhel8.cron.violations with input as i
	"CIS 5.1.9: evidence missing — at_allow_mode not collected" in v
}

test_cron_stricter_mode_accepted if {
	i := object.union(good, {"cron": {"cron_d_mode": "0500", "crontab_mode": "0400"}})
	data.cis_rhel8.cron.compliant with input as i
}

test_cron_looser_mode_flagged if {
	i := object.union(good, {"cron": {"cron_d_mode": "0755"}})
	v := data.cis_rhel8.cron.violations with input as i
	"CIS 5.1.7: /etc/cron.d has mode 0755, should be 0700" in v
}
