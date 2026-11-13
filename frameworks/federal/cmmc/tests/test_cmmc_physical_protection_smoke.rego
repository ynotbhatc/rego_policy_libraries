package cmmc.physical_protection_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_physical_protection.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_physical_protection_loads_on_empty_input if {
	m := data.cmmc.physical_protection with input as {}
	is_object(m)
}

test_cmmc_physical_protection_report_wellformed_on_empty_input if {
	report := data.cmmc.physical_protection.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_physical_protection_fail_closed_on_empty_input if {
	report := data.cmmc.physical_protection.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# --- semantic review 2026-11-13: domain verdict must agree with practices ---

good_input_review := {"physical": {"access_control_implemented": true, "authorized_personnel_list_maintained": true, "physical_access_logs_kept": true, "facility_monitoring": true, "cctv_or_equivalent": true, "environmental_controls": true, "visitor_escort_required": true, "visitor_log_maintained": true, "visitor_badges_issued": true, "physical_access_audit_logs": true, "access_log_retention_days": 90, "access_logs_reviewed_regularly": true, "access_devices_inventoried": true, "lost_credentials_revoked": true, "access_devices_audited_annually": true, "remote_work_policy": true, "alternate_site_controls_defined": true, "vpn_required_for_remote_cui_access": true}}

test_review_good_input_compliant if {
	r := data.cmmc.physical_protection.compliance_report with input as good_input_review
	r.compliant
	r.failing == 0
}

test_review_access_log_retention_missing if {
	r := data.cmmc.physical_protection.compliance_report with input as {"physical": {"access_control_implemented": true, "authorized_personnel_list_maintained": true, "physical_access_logs_kept": true, "facility_monitoring": true, "cctv_or_equivalent": true, "environmental_controls": true, "visitor_escort_required": true, "visitor_log_maintained": true, "visitor_badges_issued": true, "physical_access_audit_logs": true, "access_logs_reviewed_regularly": true, "access_devices_inventoried": true, "lost_credentials_revoked": true, "access_devices_audited_annually": true, "remote_work_policy": true, "alternate_site_controls_defined": true, "vpn_required_for_remote_cui_access": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.10.4")
}
