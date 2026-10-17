package governance.geisa.manifest_validation_test

import rego.v1

# Validation fix pass 2026-10-17.

sig := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

wrap(m) := {"geisa-application-manifest": {"manifest": m, "signature": sig}}

comm_with(field, value) := wrap({"communication": {"operator": {"daily-volume": 1, field: value}}})

test_non_string_signature_violation_not_dropped if {
	inp := {"geisa-application-manifest": {"manifest": {}, "signature": 12345}}
	v := data.governance.geisa.manifest_validation.violations with input as inp
	"geisa-application-manifest.signature: must be a 64-character hex string, got a non-string value" in v
}

test_short_string_signature_message_unchanged if {
	inp := {"geisa-application-manifest": {"manifest": {}, "signature": "abc"}}
	v := data.governance.geisa.manifest_validation.violations with input as inp
	"geisa-application-manifest.signature: must be a 64-character hex string, got 3 characters" in v
}

test_inbound_string_is_a_violation if {
	v := data.governance.geisa.manifest_validation.violations with input as comm_with("inbound", "tcp:10.0.0.1:80")
	"manifest.communication.operator.inbound: must be an array of transport:address:port strings" in v
}

test_outbound_object_is_a_violation if {
	v := data.governance.geisa.manifest_validation.violations with input as comm_with("outbound", {"a": "tcp:10.0.0.1:80"})
	"manifest.communication.operator.outbound: must be an array of transport:address:port strings" in v
}

test_valid_tap_arrays_not_flagged if {
	v := data.governance.geisa.manifest_validation.violations with input as comm_with("inbound", ["tcp:10.0.0.1:80", ":8080"])
	not has_prefix(v, "manifest.communication.operator.inbound")
}

test_bad_tap_in_array_still_flagged if {
	v := data.governance.geisa.manifest_validation.violations with input as comm_with("outbound", ["not-a-tap"])
	has_prefix(v, "manifest.communication.operator.outbound: 'not-a-tap'")
}

test_fractional_resources_flagged if {
	v := data.governance.geisa.manifest_validation.violations with input as wrap({"resources": {"app-ram": 1.5, "storage-persistent": 0.5}})
	"manifest.resources.app-ram: must be an integer >= 1" in v
	"manifest.resources.storage-persistent: must be an integer >= 0" in v
}

test_integer_resources_accepted if {
	v := data.governance.geisa.manifest_validation.violations with input as wrap({"resources": {"app-ram": 64, "storage-persistent": 0, "threads": 2.0}})
	not has_prefix(v, "manifest.resources.")
}

test_validation_report_exists_without_manifest if {
	r := data.governance.geisa.manifest_validation.validation_report with input as {}
	r.valid == false
	r.violation_count > 0
	r.app_id == null
}

test_validation_report_exists_when_manifest_not_object if {
	r := data.governance.geisa.manifest_validation.validation_report with input as {"geisa-application-manifest": {"manifest": "oops", "signature": sig}}
	r.valid == false
}

has_prefix(v, p) if {
	some m in v
	startswith(m, p)
}
