package cis_controls_v8.c05_test

import rego.v1

import data.cis_controls_v8.c05

all_attested := {"cis_controls": {"safeguards": {
	"5.1": true, "5.2": true, "5.3": true,
	"5.4": true, "5.5": true, "5.6": true,
}}}

# Empty input: every safeguard fires and the control is non-compliant.
test_empty_input_all_fire if {
	count(c05.violation) == 6 with input as {}
}

test_empty_input_not_compliant if {
	not c05.control_compliant with input as {}
}

# Fully attested: no violations, control compliant.
test_all_attested_no_violations if {
	count(c05.violation) == 0 with input as all_attested
}

test_all_attested_compliant if {
	c05.control_compliant with input as all_attested
}

# Single flip: exactly one violation, and its ID appears in the message.
test_single_flip_one_violation if {
	partial := json.patch(all_attested, [{"op": "remove", "path": "/cis_controls/safeguards/5.3"}])
	count(c05.violation) == 1 with input as partial
	some msg in c05.violation with input as partial
	contains(msg, "5.3") with input as partial
}

# compliance_report populated on empty input.
test_compliance_report_empty_input if {
	report := c05.compliance_report with input as {}
	report.control == 5
	report.safeguards_evaluated == 6
	report.violation_count == 6
	report.compliant == false
}
