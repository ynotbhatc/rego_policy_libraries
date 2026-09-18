package cis_controls_v8.c06_test

import rego.v1

import data.cis_controls_v8.c06

all_attested := {"cis_controls": {"safeguards": {
	"6.1": true, "6.2": true, "6.3": true, "6.4": true,
	"6.5": true, "6.6": true, "6.7": true, "6.8": true,
}}}

# Empty input: every safeguard fires and the control is non-compliant.
test_empty_input_all_fire if {
	count(c06.violation) == 8 with input as {}
}

test_empty_input_not_compliant if {
	not c06.control_compliant with input as {}
}

# Fully attested: no violations, control compliant.
test_all_attested_no_violations if {
	count(c06.violation) == 0 with input as all_attested
}

test_all_attested_compliant if {
	c06.control_compliant with input as all_attested
}

# Single flip: exactly one violation, and its ID appears in the message.
test_single_flip_one_violation if {
	partial := json.patch(all_attested, [{"op": "remove", "path": "/cis_controls/safeguards/6.5"}])
	count(c06.violation) == 1 with input as partial
	some msg in c06.violation with input as partial
	contains(msg, "6.5") with input as partial
}

# compliance_report populated on empty input.
test_compliance_report_empty_input if {
	report := c06.compliance_report with input as {}
	report.control == 6
	report.safeguards_evaluated == 8
	report.violation_count == 8
	report.compliant == false
}
