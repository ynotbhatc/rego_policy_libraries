package cis_postgresql.main_test

import rego.v1

test_default_is_latest_version if {
	r := data.cis_postgresql.main.compliance_report with input as {}
	r.benchmark == data.cis.postgresql_17.compliance_report.benchmark with input as {}
	r.total_controls == count(data.cis.postgresql_17.controls)
}

test_empty_input_fails_closed if {
	r := data.cis_postgresql.main.compliance_report with input as {}
	r.compliant == false
	r.passed_controls == 0
	r.failed_controls == r.total_controls
	some v in r.violations
	startswith(v, "FAIL-CLOSED: no facts supplied for cis_postgresql")
}

test_attested_control_counts_as_passed if {
	r := data.cis_postgresql.main.compliance_report with input as {"postgresql": {"attest": {"latest_security_patches_applied": true}}}
	r.passed_controls == 1
	r.failed_controls == r.total_controls - 1
	not "FAIL-CLOSED: no facts supplied for cis_postgresql — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input." in r.violations
}
