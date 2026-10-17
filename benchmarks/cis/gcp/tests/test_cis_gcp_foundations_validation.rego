package cis_gcp_foundations_test

import rego.v1

good := {
	"iam_users": [{"email": "a@corp.example.com"}],
	"audit_config": {"services": [{"audit_log_configs": [
		{"log_type": "ADMIN_READ"},
		{"log_type": "DATA_READ"},
		{"log_type": "DATA_WRITE"},
	]}]},
	"vpc_networks": [{"name": "prod"}],
	"compute_instances": [],
	"storage_buckets": [],
	"sql_instances": [],
	"bigquery_datasets": [],
}

test_complete_evidence_is_compliant if {
	data.cis_gcp_foundations.compliant with input as good
}

test_missing_sections_fail_closed if {
	inp := {"iam_users": [{"email": "a@corp.example.com"}]}
	not data.cis_gcp_foundations.compliant with input as inp
	v := data.cis_gcp_foundations.violations with input as inp
	"3: evidence missing — vpc_networks not collected" in v
	"2.1: evidence missing — audit_config.services not collected" in v
}

test_full_audit_config_not_flagged if {
	v := data.cis_gcp_foundations.violations with input as good
	count(v) == 0
}

test_admin_read_only_audit_config_flagged if {
	inp := object.union(good, {"audit_config": {"services": [{"audit_log_configs": [{"log_type": "ADMIN_READ"}]}]}})
	v := data.cis_gcp_foundations.violations with input as inp
	count([x | some x in v; startswith(x, "2.1")]) == 1
}
