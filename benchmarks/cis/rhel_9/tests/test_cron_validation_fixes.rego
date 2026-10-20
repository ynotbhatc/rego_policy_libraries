package cis_rhel9.cron_test

import rego.v1

# Validation fixes 2026-10-17: missing owner/group/mode evidence is a violation; octal modes.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 5.1.x -> v3 2.4.x.

good := {"cron": {"crond_enabled": true, "crond_running": true, "crontab_mode": "0600", "crontab_owner": "root", "crontab_group": "root", "cron_hourly_mode": "0700", "cron_hourly_owner": "root", "cron_hourly_group": "root", "cron_daily_mode": "0700", "cron_daily_owner": "root", "cron_daily_group": "root", "cron_weekly_mode": "0700", "cron_weekly_owner": "root", "cron_weekly_group": "root", "cron_monthly_mode": "0700", "cron_monthly_owner": "root", "cron_monthly_group": "root", "cron_yearly_mode": "0700", "cron_yearly_owner": "root", "cron_yearly_group": "root", "cron_d_mode": "0700", "cron_d_owner": "root", "cron_d_group": "root", "cron_allow_exists": true, "cron_allow_mode": "0640", "cron_allow_owner": "root", "cron_allow_group": "root", "cron_deny_exists": false, "at_allow_exists": true, "at_allow_mode": "0640", "at_allow_owner": "root", "at_allow_group": "root", "at_deny_exists": false}}

test_cron_good_input_compliant if {
	data.cis_rhel9.cron.compliant with input as good
}

test_cron_missing_owner_is_violation if {
	every f in ["crontab_owner", "crontab_group", "cron_hourly_owner", "cron_daily_owner", "cron_weekly_owner", "cron_monthly_owner", "cron_d_owner"] {
		not data.cis_rhel9.cron.compliant with input as json.remove(good, [concat("/", ["/cron", f])])
	}
}

test_cron_missing_mode_is_violation if {
	every f in ["crontab_mode", "cron_hourly_mode", "cron_daily_mode", "cron_weekly_mode", "cron_monthly_mode", "cron_d_mode", "cron_allow_mode", "at_allow_mode"] {
		not data.cis_rhel9.cron.compliant with input as json.remove(good, [concat("/", ["/cron", f])])
	}
}

test_cron_stricter_and_unpadded_modes_ok if {
	i := json.patch(good, [
		{"op": "replace", "path": "/cron/cron_daily_mode", "value": "0500"},
		{"op": "replace", "path": "/cron/crontab_mode", "value": "400"},
		{"op": "replace", "path": "/cron/cron_allow_mode", "value": "0400"},
	])
	data.cis_rhel9.cron.compliant with input as i
}

test_cron_loose_modes_flagged if {
	every f in ["crontab_mode", "cron_d_mode", "cron_allow_mode"] {
		i := json.patch(good, [{"op": "replace", "path": concat("/", ["/cron", f]), "value": "0777"}])
		not data.cis_rhel9.cron.compliant with input as i
	}
}
