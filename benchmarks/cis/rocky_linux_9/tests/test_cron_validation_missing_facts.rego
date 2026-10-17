package cis_rocky_linux_9.cron_test

import rego.v1

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

has(prefix, inp) if {
	v := data.cis_rocky_linux_9.cron.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_full_facts_compliant if data.cis_rocky_linux_9.cron.compliant with input as good

test_only_daemon_and_allow_facts_not_compliant if {
	inp := {"cron": {
		"crond_enabled": true, "crond_running": true,
		"cron_allow_exists": true, "cron_allow_mode": "0600",
		"at_allow_exists": true, "at_allow_mode": "0600",
	}}
	not data.cis_rocky_linux_9.cron.compliant with input as inp
	has("CIS 5.1.2", inp)
	has("CIS 5.1.3", inp)
	has("CIS 5.1.7", inp)
}

test_crontab_mode_0644_flagged if has("CIS 5.1.2", object.union(good, {"cron": {"crontab_mode": "0644"}}))

test_crontab_mode_0400_ok if not has("CIS 5.1.2", object.union(good, {"cron": {"crontab_mode": "0400"}}))

test_cron_d_mode_0777_flagged if has("CIS 5.1.7", object.union(good, {"cron": {"cron_d_mode": "0777"}}))

test_cron_allow_mode_0644_flagged if has("CIS 5.1.8", object.union(good, {"cron": {"cron_allow_mode": "0644"}}))

test_cron_allow_missing_mode_flagged if has("CIS 5.1.8", {"cron": {"cron_allow_exists": true}})

test_crontab_group_missing_flagged if {
	inp := {"cron": object.remove(good.cron, ["crontab_group"])}
	has("CIS 5.1.2: /etc/crontab group", inp)
}
