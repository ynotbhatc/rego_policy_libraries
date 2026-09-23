package cyber_essentials.secure_configuration_test

import rego.v1

import data.cyber_essentials.secure_configuration

# Build an input that attests every requirement as true.
all_true := {"cyber_essentials": {"secure_configuration": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in secure_configuration.requirements}
}

# Empty input -> every requirement fires as a violation and the theme is not compliant.
test_empty_input_all_fire if {
	count(secure_configuration.violation) == count(secure_configuration.requirements) with input as {}
	count(secure_configuration.violation) > 0 with input as {}
	not secure_configuration.theme_compliant with input as {}
}

# Fully attested -> no violations and the theme is compliant.
test_all_attested_compliant if {
	count(secure_configuration.violation) == 0 with input as all_true
	secure_configuration.theme_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	broken := object.union(all_true, {"cyber_essentials": {"secure_configuration": {"requirements": object.union(all_true.cyber_essentials.secure_configuration.requirements, {"SC-6": false})}}})
	count(secure_configuration.violation) == 1 with input as broken
	some msg in secure_configuration.violation with input as broken
	contains(msg, "SC-6") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := secure_configuration.compliance_report with input as {}
	report.theme == 2
	report.area_name == "Secure Configuration"
	report.requirements_evaluated == count(secure_configuration.requirements)
	report.violation_count == count(secure_configuration.requirements)
	report.compliant == false
}
