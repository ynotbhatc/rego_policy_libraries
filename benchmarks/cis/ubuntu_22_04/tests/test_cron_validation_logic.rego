package cis_ubuntu_22_04.cron_test

import rego.v1

# Validation fix 2026-10-17: missing cron mode/owner fields produced no violation; exact-string
# mode compares; absent allow-file modes passed.

pkg := data.cis_ubuntu_22_04.cron

good_cron := {
	"crond_enabled": true, "crond_running": true,
	"crontab_mode": "0600", "crontab_owner": "root", "crontab_group": "root",
	"cron_hourly_mode": "0700", "cron_hourly_owner": "root",
	"cron_daily_mode": "700", "cron_daily_owner": "root",
	"cron_weekly_mode": "0700", "cron_weekly_owner": "root",
	"cron_monthly_mode": "0700", "cron_monthly_owner": "root",
	"cron_d_mode": "0700", "cron_d_owner": "root",
	"cron_allow_exists": true, "cron_allow_mode": "0600",
	"at_allow_exists": true, "at_allow_mode": "0600",
}

test_good_compliant if {
	pkg.compliant with input as {"cron": good_cron}
}

test_daemon_state_only_is_not_compliant if {
	not pkg.compliant with input as {"cron": {"crond_enabled": true, "crond_running": true, "cron_allow_exists": true, "at_allow_exists": true}}
	v := pkg.violations with input as {"cron": {"crond_enabled": true, "crond_running": true}}
	"CIS 5.1.2: evidence missing — cron.crontab_mode not collected" in v
}

test_missing_owner_violates if {
	c := object.remove(good_cron, ["cron_d_owner"])
	v := pkg.violations with input as {"cron": c}
	"CIS 5.1.7: evidence missing — cron.cron_d_owner not collected" in v
}

test_group_writable_crontab_violates if {
	c := object.union(good_cron, {"crontab_mode": "0620"})
	not pkg.compliant with input as {"cron": c}
}

test_stricter_dir_mode_ok if {
	c := object.union(good_cron, {"cron_hourly_mode": "0500"})
	pkg.compliant with input as {"cron": c}
}

test_allow_mode_missing_violates if {
	c := object.remove(good_cron, ["cron_allow_mode"])
	not pkg.compliant with input as {"cron": c}
}

test_at_allow_loose_mode_violates if {
	c := object.union(good_cron, {"at_allow_mode": "0666"})
	not pkg.compliant with input as {"cron": c}
}
