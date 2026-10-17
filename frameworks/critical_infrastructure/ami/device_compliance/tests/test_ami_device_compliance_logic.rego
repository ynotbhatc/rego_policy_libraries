package ami.device.compliance_test

import rego.v1

import data.ami.device.compliance as c

# Validation 2026-10-17.

good_device := {
	"device_id": "M1",
	"firmware": {"version": "2.1.0", "signature_valid": true, "signature_algorithm": "ECDSA-P256", "ota_update_signing_required": true, "unsigned_updates_blocked": true, "rollback_protection": true},
	"certificate": {"expiry_date": "2200-01-01T00:00:00Z", "algorithm": "ECDSA-P256"},
	"key_management": {"last_rotation_date": "2200-01-01T00:00:00Z", "secure_storage": "TPM"},
	"communications": {"encrypted": true, "encryption_mode": "AES-256-GCM", "mutual_authentication": true, "encryption_algorithms": ["AES-256"]},
	"security": {"tamper_status": "ok", "tamper_detection_enabled": true, "tamper_detection_status": "operational", "secure_boot": true},
}

stds := {"minimum_firmware_version": "2.0.0"}

test_good_device_compliant if {
	c.compliant with input as {"devices": [good_device], "device_standards": stds}
}

test_empty_devices_not_compliant if {
	not c.compliant with input as {"devices": [], "device_standards": stds}
}

test_missing_algorithms_is_violation if {
	d := json.remove(good_device, ["communications/encryption_algorithms"])
	msgs := c.all_violations with input as {"devices": [d], "device_standards": stds}
	count([m | some m in msgs; contains(m, "Prohibited encryption algorithms")]) == 1
	not c.compliant with input as {"devices": [d], "device_standards": stds}
}

test_prohibited_algorithm_is_violation if {
	d := json.patch(good_device, [{"op": "replace", "path": "/communications/encryption_algorithms", "value": ["AES-256", "RC4"]}])
	msgs := c.all_violations with input as {"devices": [d], "device_standards": stds}
	count([m | some m in msgs; contains(m, "Prohibited encryption algorithms")]) == 1
}

test_prerelease_minor_segment_not_below_minimum if {
	d := json.patch(good_device, [{"op": "replace", "path": "/firmware/version", "value": "2.1-rc1"}])
	msgs := c.all_violations with input as {"devices": [d], "device_standards": stds}
	count([m | some m in msgs; contains(m, "below minimum")]) == 0
	d2 := json.patch(good_device, [{"op": "replace", "path": "/firmware/version", "value": "1.9.9"}])
	msgs2 := c.all_violations with input as {"devices": [d2], "device_standards": stds}
	count([m | some m in msgs2; contains(m, "below minimum")]) == 1
}

test_short_version_compared_with_zero_padding if {
	d := json.patch(good_device, [{"op": "replace", "path": "/firmware/version", "value": "2.1"}])
	msgs := c.all_violations with input as {"devices": [d], "device_standards": stds}
	count([m | some m in msgs; contains(m, "below minimum")]) == 0
}

test_missing_tamper_status_not_reported_as_tamper if {
	d := json.remove(good_device, ["security/tamper_status"])
	msgs := c.all_violations with input as {"devices": [d], "device_standards": stds}
	count([m | some m in msgs; contains(m, "CRITICAL")]) == 0
	count([m | some m in msgs; contains(m, "Tamper status not reported")]) == 1
}

test_tamper_detected_is_critical if {
	d := json.patch(good_device, [{"op": "replace", "path": "/security/tamper_status", "value": "tamper_detected"}])
	msgs := c.all_violations with input as {"devices": [d], "device_standards": stds}
	count([m | some m in msgs; contains(m, "CRITICAL")]) == 1
}
