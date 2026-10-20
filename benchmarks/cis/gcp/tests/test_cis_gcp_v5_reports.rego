package cis_gcp_v5_reports_test

import rego.v1

# cis_gcp.main and cis_gcp.l2 republish the cis_gcp_foundations engine (CIS GCP v5.0.0).

now_ns := 1790812800000000000

good := data.cis_gcp_foundations_v5_test.good

test_main_report_all_pass if {
	r := data.cis_gcp.main.compliance_report with input as good with time.now_ns as now_ns
	r.compliant == true
	r.version == "v5.0.0"
	r.total_controls == 93
	r.passed_controls == 93
	r.failed_controls == 0
	r.compliance_percentage == 100
	r.section_results.gke == []
	r.section_results.dataproc == []
}

test_main_report_empty_input_fails_everything if {
	r := data.cis_gcp.main.compliance_report with input as {} with time.now_ns as now_ns
	r.failed_controls == 93
	r.passed_controls == 0
	some v in r.violations
	startswith(v, "FAIL-CLOSED: no facts supplied for cis_gcp")
}

test_main_messages_prefixed_and_bucketed if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/dataproc_clusters/0/config", "value": {}},
		{"op": "replace", "path": "/compute_instances/0/canIpForward", "value": true},
	])
	r := data.cis_gcp.main.compliance_report with input as inp with time.now_ns as now_ns
	r.failed_controls == 2
	r.violation_count == 2
	r.passed_controls == 91
	count(r.section_results.dataproc) == 1
	startswith(r.section_results.dataproc[0], "CIS GCP 8.1: ")
	count(r.section_results.virtual_machines) == 1
	startswith(r.section_results.virtual_machines[0], "CIS GCP 4.6: ")
	count(r.section_results.iam) == 0
}

test_main_failed_counts_controls_not_messages if {
	inp := json.patch(good, [{"op": "add", "path": "/compute_disks/-", "value": {"name": "d2"}}, {"op": "add", "path": "/compute_disks/-", "value": {"name": "d3"}}])
	r := data.cis_gcp.main.compliance_report with input as inp with time.now_ns as now_ns
	count(r.violations) == 2
	r.failed_controls == 1
	r.passed_controls + r.failed_controls == r.total_controls
}

test_l2_report_counts if {
	r := data.cis_gcp.l2.compliance_report with input as good with time.now_ns as now_ns
	r.l2_controls == 39
	r.l2_violations == 0
	r.l2_compliant == true
}

test_l2_selects_level_2_only if {
	inp := json.patch(good, [
		{"op": "replace", "path": "/sql_instances/0/settings/databaseFlags", "value": []},
		{"op": "replace", "path": "/compute_instances/0/canIpForward", "value": true},
		{"op": "replace", "path": "/storage_buckets/0/iamConfiguration/uniformBucketLevelAccess/enabled", "value": false},
	])
	v := data.cis_gcp.l2.violations with input as inp with time.now_ns as now_ns
	count(v) == 1
	some m in v
	startswith(m, "CIS L2 5.2: ")
}
