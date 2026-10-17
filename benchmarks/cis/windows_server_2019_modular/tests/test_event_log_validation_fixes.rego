package cis_windows_server_2019.event_log_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

good := {"event_log": {
	"application_max_size": 32768, "application_retention": "OverwriteAsNeeded",
	"security_max_size": 196608, "security_retention": "OverwriteAsNeeded",
	"setup_max_size": 32768, "setup_retention": "OverwriteAsNeeded",
	"system_max_size": 32768, "system_retention": "OverwriteAsNeeded",
	"log_service_protected": true,
}}

test_event_log_good_input_compliant if {
	data.cis_windows_server_2019.event_log.compliant with input as good
}

test_event_log_setup_log_failure_not_compliant if {
	i := object.union(good, {"event_log": {"setup_max_size": 1000}})
	not data.cis_windows_server_2019.event_log.compliant with input as i
}

test_event_log_setup_failure_listed_in_violations if {
	i := object.union(good, {"event_log": {"setup_retention": "Manual"}})
	v := data.cis_windows_server_2019.event_log.violations with input as i
	count(v) == 1
}

test_event_log_report_consistent if {
	i := object.union(good, {"event_log": {"setup_max_size": 1000}})
	r := data.cis_windows_server_2019.event_log.report with input as i
	r.compliant == false
	r.total_violations == 1
	count(r.violations) == 1
}
