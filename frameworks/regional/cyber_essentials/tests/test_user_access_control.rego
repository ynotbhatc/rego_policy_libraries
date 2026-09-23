package cyber_essentials.user_access_control_test

import rego.v1

import data.cyber_essentials.user_access_control

# Build an input that attests every requirement as true.
all_true := {"cyber_essentials": {"user_access_control": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in user_access_control.requirements}
}

# Empty input -> every requirement fires as a violation and the theme is not compliant.
test_empty_input_all_fire if {
	count(user_access_control.violation) == count(user_access_control.requirements) with input as {}
	count(user_access_control.violation) > 0 with input as {}
	not user_access_control.theme_compliant with input as {}
}

# Fully attested -> no violations and the theme is compliant.
test_all_attested_compliant if {
	count(user_access_control.violation) == 0 with input as all_true
	user_access_control.theme_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"cyber_essentials": {"user_access_control": {"requirements": object.union(all_true.cyber_essentials.user_access_control.requirements, {"UA-3": false})}}})
	count(user_access_control.violation) == 1 with input as broken
	some msg in user_access_control.violation with input as broken
	contains(msg, "UA-3") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := user_access_control.compliance_report with input as {}
	report.theme == 4
	report.area_name == "User Access Control"
	report.requirements_evaluated == count(user_access_control.requirements)
	report.violation_count == count(user_access_control.requirements)
	report.compliant == false
}
