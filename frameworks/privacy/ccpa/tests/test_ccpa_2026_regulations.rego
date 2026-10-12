# Tests for the 2025 CPPA regulations modules (effective 2026-01-01):
# ccpa.cybersecurity_audits (Art. 9), ccpa.risk_assessments (Art. 10), ccpa.admt (Art. 11).
package ccpa.regulations_2026_test

import rego.v1

import data.ccpa.admt
import data.ccpa.cybersecurity_audits as audits
import data.ccpa.risk_assessments as ra

# ── Article 9 — cybersecurity audits ───────────────────────────────────────

_all_components := {id: true | some id, _ in audits.components}

_auditor_ok := {k: true | some k, _ in audits._auditor_checks}

_report_ok := {k: true | some k, _ in audits._report_checks}

_cert_ok := {k: true | some k, _ in audits._certification_checks}

_audit_input := {"ccpa": {"cybersecurity_audits": {
	"revenue_tier": "over_100m",
	"audit": {"completed": true, "covers_required_period": true},
	"auditor": object.union(_auditor_ok, {"internal": true, "reports_to_executive_without_cyber_responsibility": true}),
	"components": {
		"assessed": _all_components,
		"program_documentation_assessed": true,
		"implementation_and_enforcement_assessed": true,
	},
	"report": _report_ok,
	"certification": _cert_ok,
}}}

test_audits_empty_input_fails_closed if {
	r := audits.compliance_report with input as {}
	r.compliant == false
	r.applicable == true
	r.components_required == 18
	r.violation_count > 30
}

test_audits_full_evidence_is_compliant if {
	audits.compliant with input as _audit_input
}

test_audits_component_may_be_excused_as_not_applicable if {
	inp := json.patch(_audit_input, [
		{"op": "remove", "path": "/ccpa/cybersecurity_audits/components/assessed/c14_secure_development"},
		{"op": "add", "path": "/ccpa/cybersecurity_audits/components/not_applicable", "value": ["c14_secure_development"]},
	])
	audits.compliant with input as inp
	r := audits.compliance_report with input as inp
	r.components_assessed == 17
	r.components_not_applicable == 1
}

test_audits_missing_component_is_one_violation if {
	inp := json.patch(_audit_input, [{"op": "remove", "path": "/ccpa/cybersecurity_audits/components/assessed/c02_encryption"}])
	v := audits.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "§7123(c)(2)")
}

test_audits_internal_auditor_needs_independent_reporting_line if {
	inp := json.patch(_audit_input, [{"op": "replace", "path": "/ccpa/cybersecurity_audits/auditor/reports_to_executive_without_cyber_responsibility", "value": false}])
	v := audits.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "§7122(a)(3)")
}

test_audits_not_applicable_declaration_contradicted_by_thresholds if {
	inp := {"ccpa": {"cybersecurity_audits": {
		"applicable": false,
		"thresholds": {"meets_revenue_threshold": true, "sensitive_consumers_processed_prior_year": 60000},
	}}}
	v := audits.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "§7120(b)")
}

test_audits_not_applicable_below_thresholds_has_no_violations if {
	inp := {"ccpa": {"cybersecurity_audits": {
		"applicable": false,
		"thresholds": {"meets_revenue_threshold": true, "consumers_processed_prior_year": 1000, "sensitive_consumers_processed_prior_year": 10},
	}}}
	audits.compliant with input as inp
}

test_audits_missed_first_report_deadline_after_2028 if {
	inp := {"ccpa": {"cybersecurity_audits": {"revenue_tier": "over_100m"}}}
	v := audits.violations with input as inp with time.now_ns as time.parse_rfc3339_ns("2028-06-01T00:00:00Z")
	some msg in v
	contains(msg, "was due 2028-04-01")
}

test_audits_deadline_not_flagged_before_2028 if {
	inp := {"ccpa": {"cybersecurity_audits": {"revenue_tier": "over_100m"}}}
	v := audits.violations with input as inp with time.now_ns as time.parse_rfc3339_ns("2027-06-01T00:00:00Z")
	not _has_substring(v, "was due")
}

_has_substring(set, s) if {
	some msg in set
	contains(msg, s)
}

# ── Article 10 — risk assessments ─────────────────────────────────────────

_activities_none := {id: {"in_use": false} | some id, _ in ra.activities}

_activities_one := object.union(_activities_none, {"selling_or_sharing": {"in_use": true, "assessment_completed_before_processing": true}})

_ra_report_ok := {k: true | some k, _ in ra._report_checks}

_ra_timing_ok := {k: true | some k, _ in ra._timing_checks}

_ra_submission_ok := {k: true | some k, _ in ra._submission_checks}

_ra_input := {"ccpa": {"risk_assessments": {
	"activities": _activities_one,
	"stakeholders": {"processing_employees_included": true},
	"report": _ra_report_ok,
	"timing": _ra_timing_ok,
	"submission": _ra_submission_ok,
}}}

test_ra_empty_input_fails_closed if {
	r := ra.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 6
}

test_ra_no_activities_in_use_is_compliant_once_declared if {
	ra.compliant with input as {"ccpa": {"risk_assessments": {"activities": _activities_none}}}
}

test_ra_activity_in_use_with_full_evidence_is_compliant if {
	ra.compliant with input as _ra_input
	r := ra.compliance_report with input as _ra_input
	r.activities_in_use == ["selling_or_sharing"]
}

test_ra_activity_without_prior_assessment_is_flagged if {
	inp := json.patch(_ra_input, [{"op": "replace", "path": "/ccpa/risk_assessments/activities/selling_or_sharing/assessment_completed_before_processing", "value": false}])
	v := ra.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "§7150(b)(1)")
}

test_ra_admt_activity_requires_logic_and_output if {
	inp := json.patch(_ra_input, [{"op": "add", "path": "/ccpa/risk_assessments/activities/admt_significant_decision", "value": {"in_use": true, "assessment_completed_before_processing": true}}])
	v := ra.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "§7152(a)(3)(G)")
}

test_ra_legacy_processing_unassessed_after_deadline if {
	inp := json.patch(_ra_input, [{"op": "add", "path": "/ccpa/risk_assessments/timing/legacy_processing_continuing", "value": true}])
	v := ra.violations with input as inp with time.now_ns as time.parse_rfc3339_ns("2028-01-15T00:00:00Z")
	some msg in v
	contains(msg, "not risk-assessed by 2027-12-31")
}

test_ra_legacy_processing_scheduled_before_deadline_is_fine if {
	inp := json.patch(_ra_input, [
		{"op": "add", "path": "/ccpa/risk_assessments/timing/legacy_processing_continuing", "value": true},
		{"op": "add", "path": "/ccpa/risk_assessments/timing/legacy_assessment_scheduled", "value": true},
	])
	ra.compliant with input as inp with time.now_ns as time.parse_rfc3339_ns("2026-10-12T00:00:00Z")
}

# ── Article 11 — ADMT ─────────────────────────────────────────────────────

_notice_ok := {k: true | some k, _ in admt._notice_checks}

_opt_out_ok := {k: true | some k, _ in admt._opt_out_checks}

_access_ok := {k: true | some k, _ in admt._access_checks}

_admt_input := {"ccpa": {"admt": {
	"uses_admt_for_significant_decisions": true,
	"pre_use_notice": _notice_ok,
	"opt_out": _opt_out_ok,
	"access": _access_ok,
}}}

test_admt_empty_input_fails_closed if {
	r := admt.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 1
	r.uses_admt_for_significant_decisions == "undeclared"
}

test_admt_declared_not_used_is_compliant if {
	admt.compliant with input as {"ccpa": {"admt": {"uses_admt_for_significant_decisions": false}}}
}

test_admt_used_without_evidence_is_many_violations if {
	r := admt.compliance_report with input as {"ccpa": {"admt": {"uses_admt_for_significant_decisions": true}}}
	r.violation_count == 33
}

test_admt_full_evidence_is_compliant if {
	admt.compliant with input as _admt_input
}

test_admt_human_appeal_exception_replaces_opt_out if {
	inp := {"ccpa": {"admt": {
		"uses_admt_for_significant_decisions": true,
		"pre_use_notice": _notice_ok,
		"opt_out": {"exception": "human_appeal", "human_appeal": {"reviewer_designated_with_authority_to_overturn": true, "appeal_method_clear_and_easy": true}},
		"access": _access_ok,
	}}}
	admt.compliant with input as inp
}

test_admt_human_appeal_exception_without_reviewer_is_flagged if {
	inp := {"ccpa": {"admt": {
		"uses_admt_for_significant_decisions": true,
		"pre_use_notice": _notice_ok,
		"opt_out": {"exception": "human_appeal", "human_appeal": {"appeal_method_clear_and_easy": true}},
		"access": _access_ok,
	}}}
	v := admt.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "§7221(b)(1)(A)")
}

test_admt_unknown_exception_is_flagged_and_opt_out_not_required if {
	inp := json.patch(_admt_input, [{"op": "add", "path": "/ccpa/admt/opt_out/exception", "value": "we_said_so"}])
	v := admt.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "not one of the three recognized exceptions")
}

test_admt_cookie_banner_only_is_flagged if {
	inp := json.patch(_admt_input, [{"op": "replace", "path": "/ccpa/admt/opt_out/not_cookie_banner_only", "value": false}])
	v := admt.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "§7221(c)(4)")
}

test_admt_aggregate_response_needs_more_than_four_uses if {
	inp := json.patch(_admt_input, [{"op": "add", "path": "/ccpa/admt/access/aggregate_responses_used", "value": true}])
	v := admt.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "§7222(j)")
}

test_admt_report_carries_compliance_date if {
	r := admt.compliance_report with input as _admt_input with time.now_ns as time.parse_rfc3339_ns("2026-10-12T00:00:00Z")
	r.compliance_date == "2027-01-01"
	r.compliance_date_reached == false
}
