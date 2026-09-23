package bsi_c5.portability_interoperability_test

import rego.v1

import data.bsi_c5.portability_interoperability

# Build an input that attests every requirement as true.
all_true := {"bsi_c5": {"portability_interoperability": {"requirements": all_reqs}}} if {
	all_reqs := {id: true | some id, _ in portability_interoperability.requirements}
}

# Empty input -> every requirement fires as a violation and the domain is not compliant.
test_empty_input_all_fire if {
	count(portability_interoperability.violation) == count(portability_interoperability.requirements) with input as {}
	count(portability_interoperability.violation) > 0 with input as {}
	not portability_interoperability.domain_compliant with input as {}
}

# Fully attested -> no violations and the domain is compliant.
test_all_attested_compliant if {
	count(portability_interoperability.violation) == 0 with input as all_true
	portability_interoperability.domain_compliant with input as all_true
}

# Flip a single requirement to false -> exactly one violation naming that id.
test_single_flip_one_violation if {
	flipped := object.union(all_true.bsi_c5.portability_interoperability.requirements, {"PI-2": false})
	broken := object.union(all_true, {"bsi_c5": {"portability_interoperability": {"requirements": flipped}}})
	count(portability_interoperability.violation) == 1 with input as broken
	some msg in portability_interoperability.violation with input as broken
	contains(msg, "PI-2") with input as broken
}

# compliance_report is a populated object even on empty input.
test_compliance_report_populated if {
	report := portability_interoperability.compliance_report with input as {}
	report.domain == "PI"
	report.area_name == "Portability and Interoperability"
	report.requirements_evaluated == count(portability_interoperability.requirements)
	report.violation_count == count(portability_interoperability.requirements)
	report.compliant == false
}
