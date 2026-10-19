package cis_debian_11.sudo_test

import rego.v1

good := {"sudo": {
	"installed": true, "use_pty": true, "logfile_configured": true,
	"nopasswd_entries": [], "noauthenticate_entries": [],
	"timestamp_timeout": 5, "su_restricted": true, "su_allowed_group": "sudo",
	"sudoers_world_readable": false, "sudoers_mode": "0440",
}}

test_good_compliant if {
	data.cis_debian_11.sudo.compliant with input as good
}

test_indented_comment_ignored if {
	i := json.patch(good, [{"op": "replace", "path": "/sudo/nopasswd_entries", "value": ["  # %sudo ALL=(ALL) NOPASSWD: ALL"]}])
	data.cis_debian_11.sudo.compliant with input as i
}

test_active_nopasswd_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/sudo/nopasswd_entries", "value": ["  %sudo ALL=(ALL) NOPASSWD: ALL"]}])
	not data.cis_debian_11.sudo.compliant with input as i
}

test_indented_noauthenticate_comment_ignored if {
	i := json.patch(good, [{"op": "replace", "path": "/sudo/noauthenticate_entries", "value": ["\t# Defaults !authenticate"]}])
	data.cis_debian_11.sudo.compliant with input as i
}

test_missing_mode_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/sudo/sudoers_mode"}])
	some m in data.cis_debian_11.sudo.violations with input as i
	contains(m, "evidence missing")
}

test_mode_forms if {
	data.cis_debian_11.sudo.compliant with input as json.patch(good, [{"op": "replace", "path": "/sudo/sudoers_mode", "value": "440"}])
	not data.cis_debian_11.sudo.compliant with input as json.patch(good, [{"op": "replace", "path": "/sudo/sudoers_mode", "value": "0640"}])
}

test_missing_nopasswd_evidence_violates if {
	not data.cis_debian_11.sudo.compliant with input as json.patch(good, [{"op": "remove", "path": "/sudo/nopasswd_entries"}])
}

# Decision 2026-10-19: absent timestamp_timeout passes (sudo default 5 min).
test_timestamp_timeout_absent_passes_by_decision if {
	data.cis_debian_11.sudo.compliant with input as {"sudo": object.remove(good.sudo, ["timestamp_timeout"])}
}
