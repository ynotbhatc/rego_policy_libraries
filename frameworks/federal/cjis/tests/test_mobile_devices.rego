package cjis.mobile_devices_test

import rego.v1

import data.cjis.mobile_devices

# Empty input: every requirement fires and the area is not compliant.
test_empty_input_all_violations if {
	count(mobile_devices.violation) == count(mobile_devices.requirements) with input as {}
	not mobile_devices.area_compliant with input as {}
}

# All requirements attested: no violations, area compliant.
all_attested := {"cjis": {"mobile_devices": {"requirements": att}}} if {
	att := {id: true | some id, _ in mobile_devices.requirements}
}

test_all_attested_compliant if {
	count(mobile_devices.violation) == 0 with input as all_attested
	mobile_devices.area_compliant with input as all_attested
}

# Single flip: exactly one requirement unmet yields exactly one violation for that id.
test_single_flip_one_violation if {
	att := {id: true | some id, _ in mobile_devices.requirements}
	flipped := object.union(att, {"MD-3": false})
	in_data := {"cjis": {"mobile_devices": {"requirements": flipped}}}
	count(mobile_devices.violation) == 1 with input as in_data
	some msg in mobile_devices.violation with input as in_data
	contains(msg, "MD-3") with input as in_data
}

# Report is populated on empty input (fail-closed, not collapsed to {}).
test_report_populated_on_empty if {
	rep := mobile_devices.compliance_report with input as {}
	rep.policy_area == 13
	rep.area_name == "Mobile Devices"
	rep.requirements_evaluated == count(mobile_devices.requirements)
	rep.violation_count == count(mobile_devices.requirements)
	rep.compliant == false
}
