package stig.oracle_linux_8.software_integrity_test

import rego.v1

# Validation fixes 2026-10-17: a module with no facts collected is not compliant.

test_software_integrity_empty_input_not_compliant if {
	not data.stig.oracle_linux_8.software_integrity.compliant with input as {}
}

test_software_integrity_compliant_when_facts_collected_and_no_cat_i_open if {
	data.stig.oracle_linux_8.software_integrity.cat_i_compliant with input as {"services": {"rsyslog": "active"}}
}

test_software_integrity_report_populated_on_empty_input if {
	r := data.stig.oracle_linux_8.software_integrity.compliance_report with input as {}
	r.compliant == false
	r.open_findings == 2
	count(r.findings) == 2
}
