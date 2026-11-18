package cmmc_test_fixtures

import rego.v1

# Organisation-defined parameter values used by the CMMC tests. They equal the
# limits the modules hard-coded before 2026-11-17, so the earlier good inputs
# stay good; they are test values, not recommendations.
org_defined := {
	"session_lock_minutes": 15,
	"awareness_training_interval_days": 365,
	"audit_log_retention_days": 90,
	"audit_event_review_interval_days": 365,
	"audit_logging_managers": ["a", "b", "x"],
	"identifier_reuse_period_days": 365,
	"identifier_inactivity_days": 35,
	"password_min_length": 12,
	"password_history_generations": 5,
	"physical_access_log_retention_days": 90,
	"risk_assessment_interval_days": 365,
	"vulnerability_scan_interval_days": 30,
	"critical_vulnerability_remediation_days": 15,
	"high_vulnerability_remediation_days": 30,
	"control_assessment_interval_days": 365,
	"network_session_inactivity_minutes": 30,
	"flaw_correction_days": 30,
	"malware_scan_interval_days": 7,
}
