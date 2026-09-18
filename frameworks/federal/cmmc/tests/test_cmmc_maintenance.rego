package cmmc.maintenance_test

import rego.v1

import data.cmmc.maintenance

# =============================================================================
# Unit tests for cmmc.maintenance (CMMC 2.0 Domain 3.7 — Maintenance)
# Closes GitHub issue #84.
#
# Strategy: start from a fully-compliant maintenance fact set, then flip exactly
# one field per test so that exactly one violation rule fires. Assert the
# expected message is present in that rule's set. A fully-compliant input must
# yield zero aggregate violations; empty input must yield a populated report.
# =============================================================================

compliant_input := {"maintenance": {
	"maintenance_policy_exists": true,
	"scheduled_maintenance": true,
	"maintenance_records_kept": true,
	"maintenance_personnel_authorized": true,
	"remote_maintenance_controlled": true,
	"maintenance_tools_approved": true,
	"equipment_sanitization_procedure": true,
	"removal_authorization_required": true,
	"media_scanning_before_use": true,
	"diagnostic_media_controlled": true,
	"remote_maintenance_mfa": true,
	"remote_session_auto_terminate": true,
	"remote_maintenance_encrypted": true,
	"unauthorized_personnel_supervised": true,
	"escort_required_for_visitors": true,
}}

# --- 3.7.1 — Perform maintenance --------------------------------------------
test_violation_3_7_1_no_policy if {
	in_data := json.patch(compliant_input, [{"op": "replace", "path": "/maintenance/maintenance_policy_exists", "value": false}])
	msgs := maintenance.violation_3_7_1 with input as in_data
	"3.7.1: No documented maintenance policy for organizational systems" in msgs
}

# --- 3.7.2 — Controls on maintenance tools/personnel ------------------------
test_violation_3_7_2_personnel_unauthorized if {
	in_data := json.patch(compliant_input, [{"op": "replace", "path": "/maintenance/maintenance_personnel_authorized", "value": false}])
	msgs := maintenance.violation_3_7_2 with input as in_data
	"3.7.2: Maintenance personnel are not formally authorized and vetted" in msgs
}

# --- 3.7.3 — Sanitize equipment removed for maintenance ---------------------
test_violation_3_7_3_no_sanitization if {
	in_data := json.patch(compliant_input, [{"op": "replace", "path": "/maintenance/equipment_sanitization_procedure", "value": false}])
	msgs := maintenance.violation_3_7_3 with input as in_data
	"3.7.3: No procedure for sanitizing equipment removed for off-site maintenance" in msgs
}

# --- 3.7.4 — Scan diagnostic/test media -------------------------------------
test_violation_3_7_4_media_not_scanned if {
	in_data := json.patch(compliant_input, [{"op": "replace", "path": "/maintenance/media_scanning_before_use", "value": false}])
	msgs := maintenance.violation_3_7_4 with input as in_data
	"3.7.4: Diagnostic/test media is not scanned for malicious code before use" in msgs
}

# --- 3.7.5 — MFA for nonlocal maintenance sessions --------------------------
test_violation_3_7_5_no_mfa if {
	in_data := json.patch(compliant_input, [{"op": "replace", "path": "/maintenance/remote_maintenance_mfa", "value": false}])
	msgs := maintenance.violation_3_7_5 with input as in_data
	"3.7.5: MFA is not required for remote/nonlocal maintenance sessions" in msgs
}

# --- 3.7.6 — Supervise unauthorized maintenance personnel -------------------
test_violation_3_7_6_unsupervised if {
	in_data := json.patch(compliant_input, [{"op": "replace", "path": "/maintenance/unauthorized_personnel_supervised", "value": false}])
	msgs := maintenance.violation_3_7_6 with input as in_data
	"3.7.6: Maintenance personnel without access authorization are not supervised" in msgs
}

# --- Fully-compliant input yields no violations -----------------------------
test_no_violations_when_fully_compliant if {
	count(maintenance.all_violations) == 0 with input as compliant_input
}

test_compliant_true_when_fully_compliant if {
	maintenance.compliant with input as compliant_input
}

# --- Report is a populated object on EMPTY input ----------------------------
test_report_populated_on_empty_input if {
	report := maintenance.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}
