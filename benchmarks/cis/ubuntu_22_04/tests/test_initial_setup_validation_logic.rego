package cis_ubuntu_22_04.initial_setup_test

import rego.v1

# Validation fix 2026-10-17: absent enabled_repos/gpg_keys/mode/owner/idle-delay fields passed;
# modes were compared as exact strings.

pkg := data.cis_ubuntu_22_04.initial_setup

good := {
	"enabled_repos": ["main"], "gpg_keys": ["k"],
	"aide_installed": true, "aide_cron_configured": true,
	"grub_password_configured": true, "grub_config_mode": "0600", "grub_owner_root": true,
	"core_dumps_enabled": false, "aslr_enabled": true, "prelink_installed": false, "ptrace_scope_restricted": true,
	"motd_exists": true, "motd_mode": "0644", "motd_owner": "root", "motd_contains_sensitive_info": false,
	"issue_exists": true, "issue_mode": "0644", "issue_owner": "root", "issue_contains_sensitive_info": false,
	"issue_net_exists": true, "issue_net_mode": "0644", "issue_net_owner": "root", "issue_net_contains_sensitive_info": false,
	"gdm_installed": false,
}

inp(x) := {"initial_setup": x}

test_good_compliant if {
	pkg.compliant with input as inp(good)
}

test_missing_repos_and_keys_violate if {
	v := pkg.violations with input as inp(object.remove(good, ["enabled_repos", "gpg_keys"]))
	count(v) == 2
}

test_empty_repos_still_violate if {
	not pkg.compliant with input as inp(object.union(good, {"enabled_repos": []}))
}

test_grub_mode_without_leading_zero_ok if {
	pkg.compliant with input as inp(object.union(good, {"grub_config_mode": "600"}))
}

test_grub_mode_missing_violates if {
	not pkg.compliant with input as inp(object.remove(good, ["grub_config_mode"]))
}

test_grub_mode_loose_violates if {
	not pkg.compliant with input as inp(object.union(good, {"grub_config_mode": "0644"}))
}

test_stricter_banner_mode_ok if {
	pkg.compliant with input as inp(object.union(good, {"motd_mode": "0444"}))
}

test_banner_mode_missing_violates if {
	not pkg.compliant with input as inp(object.remove(good, ["issue_mode"]))
}

test_banner_owner_missing_violates if {
	not pkg.compliant with input as inp(object.remove(good, ["issue_net_owner"]))
}

test_core_dump_flag_missing_violates if {
	not pkg.compliant with input as inp(object.remove(good, ["core_dumps_enabled"]))
}

test_gdm_idle_delay_missing_violates if {
	gdm := object.union(good, {"gdm_installed": true, "gui_required": true, "gdm_banner_configured": true, "gdm_screen_lock_enabled": true})
	not pkg.compliant with input as inp(gdm)
	pkg.compliant with input as inp(object.union(gdm, {"gdm_idle_delay": 600}))
}
