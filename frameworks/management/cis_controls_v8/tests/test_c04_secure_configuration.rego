package cis_controls_v8.c04_test

import rego.v1

import data.cis_controls_v8.c04

all_attested := {"cis_controls": {"safeguards": {
	"4.1": true, "4.2": true, "4.3": true, "4.4": true,
	"4.5": true, "4.6": true, "4.7": true, "4.8": true,
	"4.9": true, "4.10": true, "4.11": true, "4.12": true,
}}}

# Empty input: every safeguard fires and the control is non-compliant.
test_empty_input_all_fire if {
	count(c04.violation) == 12 with input as {}
}

test_empty_input_not_compliant if {
	not c04.control_compliant with input as {}
}

# Fully attested: no violations, control compliant.
test_all_attested_no_violations if {
	count(c04.violation) == 0 with input as all_attested
}

test_all_attested_compliant if {
	c04.control_compliant with input as all_attested
}

# Single flip: exactly one violation, and its ID appears in the message.
test_single_flip_one_violation if {
	partial := json.patch(all_attested, [{"op": "remove", "path": "/cis_controls/safeguards/4.7"}])
	count(c04.violation) == 1 with input as partial
	some msg in c04.violation with input as partial
	contains(msg, "4.7") with input as partial
}

# compliance_report populated on empty input.
test_compliance_report_empty_input if {
	report := c04.compliance_report with input as {}
	report.control == 4
	report.safeguards_evaluated == 12
	report.violation_count == 12
	report.compliant == false
}
