package cis_rhel8.initial_setup_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {"initial_setup": {
	"gpg_keys": ["RPM-GPG-KEY-redhat"], "enabled_repos": ["baseos"], "repos_without_gpgcheck": [],
	"global_gpgcheck_enabled": true,
	"motd_exists": true, "motd_mode": "0644", "motd_owner": "root",
	"issue_exists": true, "issue_mode": "0644", "issue_owner": "root",
	"issue_net_exists": true, "issue_net_mode": "0644", "issue_net_owner": "root",
	"crypto_policy": "DEFAULT",
}}

test_initial_setup_fully_evidenced_is_compliant if {
	data.cis_rhel8.initial_setup.compliant with input as good
}

test_initial_setup_missing_gpg_keys_is_violation if {
	i := json.remove(good, ["initial_setup/gpg_keys"])
	"CIS 1.2.1: evidence missing — gpg_keys not collected" in data.cis_rhel8.initial_setup.violations with input as i
}

test_initial_setup_missing_enabled_repos_is_violation if {
	i := json.remove(good, ["initial_setup/enabled_repos"])
	"CIS 1.2.2: evidence missing — enabled_repos not collected" in data.cis_rhel8.initial_setup.violations with input as i
	not data.cis_rhel8.initial_setup.compliant with input as i
}

test_initial_setup_missing_owner_is_violation if {
	every k in ["motd_owner", "issue_owner", "issue_net_owner"] {
		not data.cis_rhel8.initial_setup.compliant with input as json.remove(good, [concat("/", ["initial_setup", k])])
	}
}

test_initial_setup_missing_mode_is_violation if {
	every k in ["motd_mode", "issue_mode", "issue_net_mode"] {
		not data.cis_rhel8.initial_setup.compliant with input as json.remove(good, [concat("/", ["initial_setup", k])])
	}
}

test_initial_setup_stricter_banner_mode_accepted if {
	i := object.union(good, {"initial_setup": {"motd_mode": "0600"}})
	data.cis_rhel8.initial_setup.compliant with input as i
}
