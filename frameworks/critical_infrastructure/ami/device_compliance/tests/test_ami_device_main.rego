package ami_device.main_test

import rego.v1

import data.ami_device.main as m

good_device := {
	"device_id": "M1",
	"firmware": {"version": "2.1.0", "signature_valid": true, "signature_algorithm": "ECDSA-P256", "ota_update_signing_required": true, "unsigned_updates_blocked": true, "rollback_protection": true},
	"certificate": {"expiry_date": "2200-01-01T00:00:00Z", "algorithm": "ECDSA-P256"},
	"key_management": {"last_rotation_date": "2200-01-01T00:00:00Z", "secure_storage": "TPM"},
	"communications": {"encrypted": true, "encryption_mode": "AES-256-GCM", "mutual_authentication": true, "encryption_algorithms": ["AES-256"]},
	"security": {"tamper_status": "ok", "tamper_detection_enabled": true, "tamper_detection_status": "operational", "secure_boot": true},
}

stds := {"minimum_firmware_version": "2.0.0"}

# The generic assessment playbook reads total_controls, violations and
# compliant, and refuses a report without total_controls.
test_report_meets_product_contract_on_empty_input if {
	r := m.compliance_report with input as {}
	is_object(r)
	r.total_controls == 16
	is_array(r.violations)
	r.compliant == false
}

test_empty_input_fails_closed_with_a_finding if {
	r := m.compliance_report with input as {}
	r.facts_supplied == false
	r.violation_count == 1
	r.violations[0].control == "FAIL-CLOSED"
}

test_good_fleet_is_compliant if {
	r := m.compliance_report with input as {"devices": [good_device], "device_standards": stds}
	r.compliant == true
	r.violation_count == 0
	r.facts_supplied == true
	r.total_controls == 16
}

# Regression: the bridge read _t.violations, which the module does not define,
# so every device finding was dropped from the report.
test_tampered_device_finding_reaches_the_report if {
	d := json.patch(good_device, [{"op": "replace", "path": "/security/tamper_status", "value": "tamper_detected"}])
	r := m.compliance_report with input as {"devices": [d], "device_standards": stds}
	r.compliant == false
	r.violation_count == 1
	contains(r.violations[0], "CRITICAL")
}

test_total_controls_scales_with_fleet_size if {
	r := m.compliance_report with input as {"devices": [good_device, object.union(good_device, {"device_id": "M2"})], "device_standards": stds}
	r.total_controls == 32
}

test_upstream_fields_are_kept if {
	r := m.compliance_report with input as {"devices": [good_device], "device_standards": stds}
	r.framework == "AMI 2.0 Device Compliance"
	r.total_devices == 1
}
