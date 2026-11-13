package ami_headend.main_test

import rego.v1

import data.ami_headend.main as m

# The generic assessment playbook reads total_controls, violations and
# compliant, and refuses a report without total_controls.
test_report_meets_product_contract_on_empty_input if {
	r := m.compliance_report with input as {}
	is_object(r)
	r.total_controls >= 19
	is_array(r.violations)
	r.compliant == false
}

# On empty input the module already reports every control open; the bridge
# appends one FAIL-CLOSED finding so the reason is recorded, and never lets
# total_controls fall below the violation count.
test_empty_input_fails_closed_with_a_finding if {
	up := data.ami.headend.security.violations with input as {}
	r := m.compliance_report with input as {}
	r.facts_supplied == false
	r.violation_count == count(up) + 1
	r.violations[count(up)].control == "FAIL-CLOSED"
	r.total_controls >= r.violation_count
}

test_facts_without_findings_do_not_add_the_fail_closed_finding if {
	r := m.compliance_report with input as {"headend": {}}
	r.facts_supplied == true
	not r.violations[count(r.violations) - 1].control == "FAIL-CLOSED"
}

test_upstream_violations_pass_through if {
	up := data.ami.headend.security.violations with input as {"headend": {}}
	r := m.compliance_report with input as {"headend": {}}
	r.violation_count == count(up)
	r.framework == "AMI Head-End Security"
}
