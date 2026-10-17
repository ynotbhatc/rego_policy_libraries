package cis_ubuntu_20_04.initial_setup_test

import rego.v1

# Validation fix pass 2026-10-17.

good := {"initial_setup": {
	"enabled_repos": ["main"], "gpg_keys": ["k1"],
	"aide_installed": true, "aide_cron_configured": true,
	"grub_password_configured": true, "grub_config_mode": "0400", "grub_owner_root": true,
	"core_dumps_enabled": false, "aslr_enabled": true, "prelink_installed": false, "ptrace_scope_restricted": true,
	"motd_exists": true, "motd_mode": "0644", "motd_owner": "root",
	"issue_exists": true, "issue_mode": "0644", "issue_owner": "root",
	"issue_net_exists": true, "issue_net_mode": "644", "issue_net_owner": "root",
}}

test_good_input_compliant if {
	data.cis_ubuntu_20_04.initial_setup.compliant with input as good
}

test_missing_repo_and_gpg_evidence_flagged if {
	inp := json.remove(good, ["initial_setup/enabled_repos", "initial_setup/gpg_keys"])
	v := data.cis_ubuntu_20_04.initial_setup.violations with input as inp
	count({m | some m in v; contains(m, "evidence missing")}) == 2
}

test_missing_grub_mode_and_owner_flagged if {
	inp := json.remove(good, ["initial_setup/grub_config_mode", "initial_setup/motd_owner"])
	not data.cis_ubuntu_20_04.initial_setup.compliant with input as inp
}

test_banner_exists_without_mode_flagged if {
	inp := json.remove(good, ["initial_setup/issue_mode"])
	not data.cis_ubuntu_20_04.initial_setup.compliant with input as inp
}

test_grub_mode_644_flagged if {
	not data.cis_ubuntu_20_04.initial_setup.compliant with input as object.union(good, {"initial_setup": {"grub_config_mode": "0644"}})
}

test_banner_mode_664_flagged if {
	not data.cis_ubuntu_20_04.initial_setup.compliant with input as object.union(good, {"initial_setup": {"motd_mode": "0664"}})
}

test_more_restrictive_banner_mode_accepted if {
	data.cis_ubuntu_20_04.initial_setup.compliant with input as object.union(good, {"initial_setup": {"issue_mode": "0600", "grub_config_mode": "400"}})
}
