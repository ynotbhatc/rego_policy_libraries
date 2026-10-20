package cis_gcp_foundations_test

import rego.v1

# Rewritten for CIS GCP Foundation Benchmark v5.0.0 (same test names as before). The complete
# fixture lives in test_cis_gcp_v5_controls.rego.

now_ns := 1790812800000000000

good := data.cis_gcp_foundations_v5_test.good

test_complete_evidence_is_compliant if {
	data.cis_gcp_foundations.compliant with input as good with time.now_ns as now_ns
}

test_missing_sections_fail_closed if {
	inp := {"iam_users": [{"email": "a@corp.example.com"}]}
	not data.cis_gcp_foundations.compliant with input as inp
	v := data.cis_gcp_foundations.violations with input as inp
	"3.1: evidence missing — vpc_networks not collected" in v
	"2.1: evidence missing — iam_policy not collected" in v
}

test_full_audit_config_not_flagged if {
	v := data.cis_gcp_foundations.violations with input as good with time.now_ns as now_ns
	count(v) == 0
}

test_admin_read_only_audit_config_flagged if {
	inp := json.patch(good, [{"op": "replace", "path": "/iam_policy/auditConfigs", "value": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}]}])
	v := data.cis_gcp_foundations.violations with input as inp with time.now_ns as now_ns
	count([x | some x in v; startswith(x, "2.1")]) == 1
}
