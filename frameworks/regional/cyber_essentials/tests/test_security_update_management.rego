package cyber_essentials.security_update_management_test

import rego.v1

import data.cyber_essentials.security_update_management

# Build an input that attests every requirement as true.
all_true := {"cyber_essentials": {"security_update_management": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in security_update_management.requirements}
}

# Empty input -> every requirement fires as a violation and the theme is not compliant.
test_empty_input_all_fire if {
	count(security_update_management.violation) == count(security_update_management.requirements) with input as {}
	count(security_update_management.violation) > 0 with input as {}
	not security_update_management.theme_compliant with input as {}
}

# Fully attested -> no violations and the theme is compliant.
test_all_attested_compliant if {
	count(security_update_management.violation) == 0 with input as all_true
	security_update_management.theme_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.cyber_essentials.security_update_management.requirements, {"SU-4": false})
	broken := object.union(all_true, {"cyber_essentials": {"security_update_management": {"requirements": flipped}}})
	count(security_update_management.violation) == 1 with input as broken
	some msg in security_update_management.violation with input as broken
	contains(msg, "SU-4") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := security_update_management.compliance_report with input as {}
	report.theme == 3
	report.area_name == "Security Update Management"
	report.requirements_evaluated == count(security_update_management.requirements)
	report.violation_count == count(security_update_management.requirements)
	report.compliant == false
}
