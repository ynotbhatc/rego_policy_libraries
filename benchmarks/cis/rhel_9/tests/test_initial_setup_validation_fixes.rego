package cis_rhel9.initial_setup_test

import rego.v1

# Validation fixes 2026-10-17: missing gpg/repo/owner/mode evidence is a violation; octal modes.

good := {"initial_setup": {
	"gpg_keys": ["RPM-GPG-KEY-redhat-release"], "enabled_repos": ["baseos"], "global_gpgcheck_enabled": true,
	"motd_exists": true, "motd_mode": "0644", "motd_owner": "root",
	"issue_exists": true, "issue_mode": "0644", "issue_owner": "root",
	"issue_net_exists": true, "issue_net_mode": "0644", "issue_net_owner": "root",
	"crypto_policy": "DEFAULT",
}}

test_initial_setup_good_input_compliant if {
	data.cis_rhel9.initial_setup.compliant with input as good
}

test_initial_setup_missing_gpg_keys_is_violation if {
	not data.cis_rhel9.initial_setup.compliant with input as json.remove(good, ["/initial_setup/gpg_keys"])
}

test_initial_setup_missing_enabled_repos_is_violation if {
	not data.cis_rhel9.initial_setup.compliant with input as json.remove(good, ["/initial_setup/enabled_repos"])
}

test_initial_setup_missing_owner_is_violation if {
	every f in ["motd_owner", "issue_owner", "issue_net_owner"] {
		not data.cis_rhel9.initial_setup.compliant with input as json.remove(good, [concat("", ["/initial_setup/", f])])
	}
}

test_initial_setup_missing_mode_is_violation if {
	every f in ["motd_mode", "issue_mode", "issue_net_mode"] {
		not data.cis_rhel9.initial_setup.compliant with input as json.remove(good, [concat("", ["/initial_setup/", f])])
	}
}

test_initial_setup_stricter_mode_ok if {
	i := json.patch(good, [{"op": "replace", "path": "/initial_setup/motd_mode", "value": "0600"}, {"op": "replace", "path": "/initial_setup/issue_mode", "value": "644"}])
	data.cis_rhel9.initial_setup.compliant with input as i
}

test_initial_setup_writable_mode_flagged if {
	i := json.patch(good, [{"op": "replace", "path": "/initial_setup/issue_net_mode", "value": "0664"}])
	not data.cis_rhel9.initial_setup.compliant with input as i
}
