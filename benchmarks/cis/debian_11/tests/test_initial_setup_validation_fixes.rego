package cis_debian_11.initial_setup_test

import rego.v1

good := {"initial_setup": {
	"enabled_repos": ["main"], "gpg_keys": ["k"],
	"aide_installed": true, "aide_cron_configured": true,
	"grub_password_configured": true, "grub_config_mode": "0400", "grub_owner_root": true,
	"core_dumps_enabled": false, "aslr_enabled": true, "prelink_installed": false, "ptrace_scope_restricted": true,
	"motd_exists": true, "motd_mode": "0644", "motd_owner": "root", "motd_contains_sensitive_info": false,
	"issue_exists": true, "issue_mode": "0644", "issue_owner": "root", "issue_contains_sensitive_info": false,
	"issue_net_exists": true, "issue_net_mode": "0644", "issue_net_owner": "root", "issue_net_contains_sensitive_info": false,
	"gdm_installed": false,
}}

test_good_compliant if {
	data.cis_debian_11.initial_setup.compliant with input as good
}

test_missing_repos_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/initial_setup/enabled_repos"}])
	some m in data.cis_debian_11.initial_setup.violations with input as i
	contains(m, "enabled_repos")
}

test_missing_gpg_keys_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/initial_setup/gpg_keys"}])
	not data.cis_debian_11.initial_setup.compliant with input as i
}

test_missing_owner_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/initial_setup/issue_owner"}])
	not data.cis_debian_11.initial_setup.compliant with input as i
}

test_missing_mode_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/initial_setup/motd_mode"}])
	not data.cis_debian_11.initial_setup.compliant with input as i
}

test_missing_grub_mode_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/initial_setup/grub_config_mode"}])
	not data.cis_debian_11.initial_setup.compliant with input as i
}

test_octal_forms_ok if {
	i := json.patch(good, [
		{"op": "replace", "path": "/initial_setup/grub_config_mode", "value": "400"},
		{"op": "replace", "path": "/initial_setup/motd_mode", "value": "0o644"},
		{"op": "replace", "path": "/initial_setup/issue_mode", "value": "444"},
	])
	data.cis_debian_11.initial_setup.compliant with input as i
}

test_loose_mode_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/initial_setup/issue_mode", "value": "0666"}])
	not data.cis_debian_11.initial_setup.compliant with input as i
}
