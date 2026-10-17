package ami.nist_ir7628.identification_auth_test

import rego.v1

import data.ami.nist_ir7628.identification_auth as ia

# Validation 2026-10-17: empty/missing inventories are not a pass.

base := {"identification_auth": {
	"devices": {
		"unique_identity_per_device": true,
		"authentication_required": true,
		"unauthenticated_devices_blocked": true,
		"credential_inventory": [{"device_id": "d1", "last_key_rotation_date": "2200-01-01T00:00:00Z"}],
	},
	"pki": {
		"certificate_authority_trusted": true,
		"certificate_algorithm": "ECDSA-P256",
		"certificate_revocation_checking": true,
		"device_certificates": [{"device_id": "d1", "expiry_date": "2200-01-01T00:00:00Z"}],
	},
	"cryptography": {"fips_validated": true, "validation_level": 2},
	"mfa": {"enabled": true, "required_for_privileged": true, "second_factor": "totp"},
}}

test_full_evidence_compliant if {
	ia.compliant with input as base
}

test_empty_credential_inventory_not_rotated if {
	i := json.patch(base, [{"op": "replace", "path": "/identification_auth/devices/credential_inventory", "value": []}])
	not ia.key_rotation_current with input as i
	not ia.compliant with input as i
	count([m | some m in ia.violations with input as i; contains(m, "evidence missing")]) == 1
}

test_missing_certs_message_not_empty_list if {
	i := json.remove(base, ["identification_auth/pki/device_certificates"])
	v := ia.violations with input as i
	count([m | some m in v; contains(m, "evidence missing")]) == 1
	count([m | some m in v; contains(m, "expiring within 30 days")]) == 0
}

test_unreadable_rotation_date_flagged if {
	i := json.patch(base, [{"op": "replace", "path": "/identification_auth/devices/credential_inventory", "value": [{"device_id": "d9", "last_key_rotation_date": "yesterday"}]}])
	v := ia.violations with input as i
	count([m | some m in v; contains(m, "d9")]) == 1
}
