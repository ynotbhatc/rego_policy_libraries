package cis_rocky_linux_9.initial_setup_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_rocky_linux_9.initial_setup.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_absent_gpg_keys_flagged if has("CIS 1.2.1", {"initial_setup": {}})
test_empty_gpg_keys_flagged if has("CIS 1.2.1", {"initial_setup": {"gpg_keys": []}})
test_gpg_keys_present_ok if not has("CIS 1.2.1", {"initial_setup": {"gpg_keys": ["k"]}})
test_absent_repos_flagged if has("CIS 1.2.2: No package", {"initial_setup": {}})

test_absent_owner_facts_flagged if {
	has("CIS 1.7.4", {"initial_setup": {}})
	has("CIS 1.7.5", {"initial_setup": {}})
	has("CIS 1.7.6", {"initial_setup": {}})
}

test_root_owner_ok if not has("CIS 1.7.4", {"initial_setup": {"motd_owner": "root"}})
test_motd_mode_0640_ok if not has("CIS 1.7.1: /etc/motd has mode", {"initial_setup": {"motd_exists": true, "motd_mode": "0640"}})
test_motd_mode_0666_flagged if has("CIS 1.7.1: /etc/motd has mode", {"initial_setup": {"motd_exists": true, "motd_mode": "0666"}})
test_missing_gdm_facts_flagged if has("CIS 1.8: evidence missing", {"initial_setup": {}})
test_gdm_not_installed_ok if not has("CIS 1.8:", {"initial_setup": {"gdm_installed": false}})
test_gdm_installed_without_gui_required_flagged if has("CIS 1.8: evidence missing — initial_setup.gui_required", {"initial_setup": {"gdm_installed": true}})
