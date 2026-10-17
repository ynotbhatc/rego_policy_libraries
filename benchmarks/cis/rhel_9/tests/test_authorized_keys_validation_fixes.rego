package cis_rhel9.authorized_keys_test

import rego.v1

# Validation fixes 2026-10-17: an empty authorized_keys object is not evidence; octal modes.

good := {"authorized_keys": {
	"files": [{"path": "/home/a/.ssh/authorized_keys", "user": "a", "expected_owner": "a", "owner": "a", "mode": "0600", "keys": [{"type": "ssh-ed25519", "bits": 256, "fingerprint": "SHA256:x", "comment": "a@host", "age_minutes": 9999}]}],
	"ssh_dirs": [{"path": "/home/a/.ssh", "mode": "0700"}],
}}

test_authorized_keys_empty_object_is_not_compliant if {
	not data.cis_rhel9.authorized_keys.compliant with input as {"authorized_keys": {}}
	some v in data.cis_rhel9.authorized_keys.violations with input as {"authorized_keys": {}}
	contains(v, "evidence missing")
}

test_authorized_keys_good_input_is_compliant if {
	data.cis_rhel9.authorized_keys.compliant with input as good
}

test_authorized_keys_empty_collections_are_evidence if {
	data.cis_rhel9.authorized_keys.compliant with input as {"authorized_keys": {"files": [], "ssh_dirs": []}}
}

test_authorized_keys_missing_ssh_dirs_flagged if {
	i := {"authorized_keys": {"files": []}}
	not data.cis_rhel9.authorized_keys.compliant with input as i
}

test_authorized_keys_group_writable_flagged if {
	i := json.patch(good, [{"op": "replace", "path": "/authorized_keys/files/0/mode", "value": "0660"}])
	not data.cis_rhel9.authorized_keys.compliant with input as i
}

test_authorized_keys_unparsable_mode_flagged if {
	i := json.patch(good, [{"op": "replace", "path": "/authorized_keys/files/0/mode", "value": "rw-r--r--"}])
	not data.cis_rhel9.authorized_keys.compliant with input as i
}

test_authorized_keys_0o_prefix_world_writable_flagged if {
	i := json.patch(good, [{"op": "replace", "path": "/authorized_keys/files/0/mode", "value": "0o666"}])
	not data.cis_rhel9.authorized_keys.compliant with input as i
}

test_authorized_keys_stricter_ssh_dir_mode_ok if {
	i := json.patch(good, [{"op": "replace", "path": "/authorized_keys/ssh_dirs/0/mode", "value": "0500"}])
	data.cis_rhel9.authorized_keys.compliant with input as i
}

test_authorized_keys_loose_ssh_dir_flagged if {
	i := json.patch(good, [{"op": "replace", "path": "/authorized_keys/ssh_dirs/0/mode", "value": "0755"}])
	not data.cis_rhel9.authorized_keys.compliant with input as i
}
