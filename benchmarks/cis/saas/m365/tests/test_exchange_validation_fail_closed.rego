package cis_m365.exchange_test

import rego.v1

test_not_compliant_without_facts if {
	r := data.cis_m365.exchange.compliance_report with input as {}
	not r.compliant == true
	r.violation_count > 0
}
