package zero_trust.devices_test

import rego.v1

import data.zero_trust.devices

# Build an input that attests every criterion as true.
all_true := {"zero_trust": {"devices": {"criteria": {id: true |
	some id, _ in devices.criteria
}}}}

# Empty attestation → every criterion fires a violation and pillar is not compliant.
test_empty_input_all_fire if {
	inp := {"zero_trust": {"devices": {"criteria": {}}}}
	count(devices.violation) == count(devices.criteria) with input as inp
	not devices.pillar_compliant with input as inp
}

# Fully attested → no violations and pillar is compliant.
test_all_attested_compliant if {
	count(devices.violation) == 0 with input as all_true
	devices.pillar_compliant with input as all_true
}

# Flipping a single criterion to false yields exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true, {"zero_trust": {"devices": {"criteria": {"DEV-5": false}}}})
	count(devices.violation) == 1 with input as flipped
	not devices.pillar_compliant with input as flipped
	some msg in devices.violation with input as flipped
	contains(msg, "DEV-5") with input as flipped
}

# Report is populated on empty input.
test_report_populated_on_empty if {
	inp := {"zero_trust": {"devices": {"criteria": {}}}}
	report := devices.compliance_report with input as inp
	report.pillar == "Devices"
	report.criteria_evaluated == count(devices.criteria)
	report.violation_count == count(devices.criteria)
	report.compliant == false
}
