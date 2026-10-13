package cis_m365_v7.main_test

import rego.v1

test_not_compliant_without_facts if {
	r := data.cis_m365_v7.main.compliance_report with input as {}
	r.assessed_controls_compliant == false
	r.violation_count > 0
}
