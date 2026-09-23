package cyber_essentials.firewalls_test

import rego.v1

import data.cyber_essentials.firewalls

# Build an input that attests every requirement as true.
all_true := {"cyber_essentials": {"firewalls": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in firewalls.requirements}
}

# Empty input -> every requirement fires as a violation and the theme is not compliant.
test_empty_input_all_fire if {
	count(firewalls.violation) == count(firewalls.requirements) with input as {}
	count(firewalls.violation) > 0 with input as {}
	not firewalls.theme_compliant with input as {}
}

# Fully attested -> no violations and the theme is compliant.
test_all_attested_compliant if {
	count(firewalls.violation) == 0 with input as all_true
	firewalls.theme_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"cyber_essentials": {"firewalls": {"requirements": object.union(all_true.cyber_essentials.firewalls.requirements, {"FW-4": false})}}})
	count(firewalls.violation) == 1 with input as broken
	some msg in firewalls.violation with input as broken
	contains(msg, "FW-4") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := firewalls.compliance_report with input as {}
	report.theme == 1
	report.area_name == "Firewalls"
	report.requirements_evaluated == count(firewalls.requirements)
	report.violation_count == count(firewalls.requirements)
	report.compliant == false
}
