package bsi_c5.supplier_control_test

import rego.v1

import data.bsi_c5.supplier_control

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"supplier_control": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in supplier_control.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(supplier_control.violation) == count(supplier_control.requirements) with input as {}
	count(supplier_control.violation) > 0 with input as {}
	not supplier_control.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(supplier_control.violation) == 0 with input as all_true
	supplier_control.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.supplier_control.requirements, {"SSO-2": false})
	broken := object.union(all_true, {"bsi_c5": {"supplier_control": {"requirements": flipped}}})
	count(supplier_control.violation) == 1 with input as broken
	some msg in supplier_control.violation with input as broken
	contains(msg, "SSO-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := supplier_control.compliance_report with input as {}
	report.domain == "SSO"
	report.area_name == "Control and Monitoring of Service Providers and Suppliers"
	report.requirements_evaluated == count(supplier_control.requirements)
	report.violation_count == count(supplier_control.requirements)
	report.compliant == false
}
