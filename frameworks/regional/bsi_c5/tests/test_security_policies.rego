package bsi_c5.security_policies_test

import rego.v1

import data.bsi_c5.security_policies

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"security_policies": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in security_policies.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(security_policies.violation) == count(security_policies.requirements) with input as {}
	count(security_policies.violation) > 0 with input as {}
	not security_policies.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(security_policies.violation) == 0 with input as all_true
	security_policies.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.security_policies.requirements, {"SP-2": false})
	broken := object.union(all_true, {"bsi_c5": {"security_policies": {"requirements": flipped}}})
	count(security_policies.violation) == 1 with input as broken
	some msg in security_policies.violation with input as broken
	contains(msg, "SP-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := security_policies.compliance_report with input as {}
	report.domain == "SP"
	report.area_name == "Security Policies and Instructions"
	report.requirements_evaluated == count(security_policies.requirements)
	report.violation_count == count(security_policies.requirements)
	report.compliant == false
}
