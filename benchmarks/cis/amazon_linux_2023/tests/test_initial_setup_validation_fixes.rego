package cis_amazon_linux_2023.initial_setup_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

base := {"initial_setup": {
	"gpg_keys": ["k"], "enabled_repos": ["r"], "global_gpgcheck_enabled": true,
	"motd_exists": true, "motd_mode": "0644", "motd_owner": "root",
	"issue_exists": true, "issue_mode": "0644", "issue_owner": "root",
	"issue_net_exists": true, "issue_net_mode": "0644", "issue_net_owner": "root",
	"crypto_policy": "DEFAULT",
}}

test_initial_setup_good_input_compliant if {
	data.cis_amazon_linux_2023.initial_setup.compliant with input as base
}

test_initial_setup_stricter_mode_ok if {
	i := object.union(base, {"initial_setup": {"motd_mode": "0600"}})
	data.cis_amazon_linux_2023.initial_setup.compliant with input as i
}

test_initial_setup_missing_banner_mode_and_owner_not_compliant if {
	i := {"initial_setup": object.remove(base.initial_setup, ["motd_mode", "motd_owner", "issue_mode", "issue_owner", "issue_net_mode", "issue_net_owner"])}
	not data.cis_amazon_linux_2023.initial_setup.compliant with input as i
	v := data.cis_amazon_linux_2023.initial_setup.violations with input as i
	count([m | some m in v; contains(m, "evidence missing")]) == 6
}

test_initial_setup_permissive_banner_mode_flagged if {
	i := object.union(base, {"initial_setup": {"issue_mode": "0666"}})
	not data.cis_amazon_linux_2023.initial_setup.compliant with input as i
}

gdm := object.union(base, {"initial_setup": {
	"gdm_installed": true, "gui_required": true, "gdm_banner_configured": true,
	"gdm_disable_user_list": true, "gdm_screen_lock_enabled": true,
	"gdm_automount_disabled": true, "gdm_automount_open_disabled": true,
	"gdm_autorun_never_enabled": true,
}})

test_initial_setup_gdm_idle_delay_string_not_misflagged if {
	i := object.union(gdm, {"initial_setup": {"gdm_idle_delay": "300"}})
	data.cis_amazon_linux_2023.initial_setup.compliant with input as i
}

test_initial_setup_gdm_idle_delay_string_too_long_flagged_cleanly if {
	i := object.union(gdm, {"initial_setup": {"gdm_idle_delay": "1200"}})
	v := data.cis_amazon_linux_2023.initial_setup.violations with input as i
	"CIS 1.8.4: GDM idle delay is 1200 seconds, should be 900 or less" in v
}

test_initial_setup_gdm_idle_delay_missing_flagged if {
	v := data.cis_amazon_linux_2023.initial_setup.violations with input as gdm
	"CIS 1.8.4: evidence missing - initial_setup.gdm_idle_delay not collected" in v
}
