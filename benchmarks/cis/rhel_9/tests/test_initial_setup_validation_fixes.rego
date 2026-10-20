package cis_rhel9.initial_setup_test

import rego.v1

# Validation fixes 2026-10-17: missing gpg/repo/owner/mode evidence is a violation; octal modes.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# GPG key review (v3 1.2.1.1) is Manual in v3.0.0: the gpg-keys test now removes that attestation.

good := {"attest": {"gpg_keys_reviewed": true, "repositories_reviewed": true, "updates_installed": true, "crypto_policy_chacha20_ssh_reviewed": true, "crypto_policy_etm_ssh_reviewed": true}, "initial_setup": {"global_gpgcheck_enabled": true, "repos_without_gpgcheck": [], "enabled_repos": ["baseos"], "dnf_conf_raw": "[main]\nrepo_gpgcheck=1\n[main]\ninstall_weak_deps=False", "crypto_policy": "DEFAULT:PQ", "motd_exists": true, "motd_contains_sensitive_info": false, "issue_exists": true, "issue_contains_sensitive_info": false, "issue_net_exists": true, "issue_net_contains_sensitive_info": false, "motd_mode": "0644", "motd_owner": "root", "motd_group": "root", "issue_mode": "0644", "issue_owner": "root", "issue_group": "root", "issue_net_mode": "0644", "issue_net_owner": "root", "issue_net_group": "root", "gdm_banner_configured": true, "gdm_banner_override_allowed": false, "gdm_installed": true, "gdm_disable_user_list": true, "gdm_disable_user_list_override_allowed": false, "gdm_idle_delay": 900, "gdm_lock_delay": 5, "gdm_lock_override_allowed": false, "gdm_automount_disabled": true, "gdm_automount_open_disabled": true, "gdm_automount_override_allowed": false, "gdm_autorun_never_enabled": true, "gdm_autorun_override_allowed": false, "gdm_xdmcp_enabled": false, "gdm_wayland_disabled": false}, "crypto_policy": {"current_pol_raw": "hash = SHA2-256 SHA2-384\nsign = RSA-PSS-SHA2-256\nhash@RPM = SHA2-256 SHA1\nsha1_in_certs = 0\nmac = HMAC-SHA2-256 UMAC-128\ncipher = AES-256-GCM AES-128-GCM\ncipher@openssh-server = AES-256-GCM", "pq_module_available": true}}

test_initial_setup_good_input_compliant if {
	data.cis_rhel9.initial_setup.compliant with input as good
}

test_initial_setup_missing_gpg_keys_is_violation if {
	not data.cis_rhel9.initial_setup.compliant with input as json.remove(good, ["/attest/gpg_keys_reviewed"])
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
