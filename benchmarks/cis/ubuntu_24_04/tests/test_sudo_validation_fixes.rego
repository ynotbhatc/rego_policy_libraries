package cis_ubuntu_24_04.sudo_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {"sudo": {
	"installed": true, "use_pty": true, "logfile_configured": true,
	"nopasswd_entries": [], "noauthenticate_entries": [],
	"timestamp_timeout": 15, "su_restricted": true,
	"sudoers_world_readable": false, "sudoers_mode": "0440",
}}

test_sudo_fully_evidenced_is_compliant if {
	data.cis_ubuntu_24_04.sudo.compliant with input as good
}

test_sudo_missing_timestamp_timeout_is_violation if {
	i := json.remove(good, ["sudo/timestamp_timeout"])
	"CIS 5.3: evidence missing — sudo.timestamp_timeout not collected" in data.cis_ubuntu_24_04.sudo.violations with input as i
	not data.cis_ubuntu_24_04.sudo.compliant with input as i
}

test_sudo_missing_sudoers_mode_is_violation if {
	i := json.remove(good, ["sudo/sudoers_mode"])
	"CIS 5.3: evidence missing — sudo.sudoers_mode not collected" in data.cis_ubuntu_24_04.sudo.violations with input as i
}

test_sudo_missing_entry_lists_are_violations if {
	every k in ["nopasswd_entries", "noauthenticate_entries"] {
		not data.cis_ubuntu_24_04.sudo.compliant with input as json.remove(good, [concat("/", ["sudo", k])])
	}
}

test_sudoers_mode_octal if {
	every m in ["0440", "0400", "0040"] {
		data.cis_ubuntu_24_04.sudo.compliant with input as object.union(good, {"sudo": {"sudoers_mode": m}})
	}
	every m in ["0640", "0444", "0441"] {
		not data.cis_ubuntu_24_04.sudo.compliant with input as object.union(good, {"sudo": {"sudoers_mode": m}})
	}
}
