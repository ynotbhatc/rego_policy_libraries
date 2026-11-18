package soc2.criteria_test

import rego.v1

import data.soc2.main
import data.soc2.security.access_controls as ac

# Audit 2026-11-17 finding 9: the report scores Trust Services Criteria by id, and
# organization-defined values come from the entity's own commitments.

_cc_ids := {
	"CC1.1", "CC1.2", "CC1.3", "CC1.4", "CC1.5", "CC2.1", "CC2.2", "CC2.3", "CC3.1", "CC3.2", "CC3.3",
	"CC3.4", "CC4.1", "CC4.2", "CC5.1", "CC5.2", "CC5.3", "CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5",
	"CC6.6", "CC6.7", "CC6.8", "CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5", "CC8.1", "CC9.1", "CC9.2",
}

test_scored_criteria_are_real_common_criteria if {
	count(_cc_ids) == 33
	ids := {c | some c, _ in main.criteria_checks}
	count(ids) == 12
	every c in ids {
		c in _cc_ids
	}
}

test_empty_input_scores_twelve_criteria_all_failed if {
	r := main.compliance_report with input as {}
	r.total_controls == 12
	r.failed_controls == 12
	r.compliant == false
	"SOC 2 CC6.6: check security.remote_access_secured not satisfied" in r.violations
	"SOC 2 CC6.6: evidence missing - input.soc2.commitments.max_idle_minutes (the entity's stated value) not supplied or not a number" in r.violations
	"SOC 2 CC7.2: evidence missing - input.access_controls.access_logging.retention_days not collected or not a number" in r.violations
	some v in r.violations
	startswith(v, "SOC 2 scope: evidence missing - input.soc2.categories_in_scope")
}

# --- idle timeout: actual against the entity's commitment (CC6.6) ---

_remote(idle, commitment) := {
	"remote_access": {"vpn_required": true, "vpn_encryption": {"enabled": true}, "session_timeout": {"configured": true, "max_idle_minutes": idle}},
	"soc2": {"commitments": {"max_idle_minutes": commitment}},
}

test_idle_timeout_within_commitment_passes if {
	ac.remote_access_secured with input as _remote(45, 60)
}

test_idle_timeout_over_commitment_fails if {
	not ac.remote_access_secured with input as _remote(45, 30)
}

test_idle_timeout_without_commitment_fails_closed if {
	inp := json.remove(_remote(10, 60), ["/soc2/commitments/max_idle_minutes"])
	not ac.remote_access_secured with input as inp
	f := ac.evidence_findings with input as inp
	"CC6.6: evidence missing - input.soc2.commitments.max_idle_minutes (the entity's stated value) not supplied or not a number" in f
}

test_idle_timeout_without_observed_value_fails_closed if {
	inp := json.remove(_remote(10, 60), ["/remote_access/session_timeout/max_idle_minutes"])
	not ac.remote_access_secured with input as inp
	f := ac.evidence_findings with input as inp
	"CC6.6: evidence missing - input.remote_access.session_timeout.max_idle_minutes not collected or not a number" in f
}

# --- log retention (CC7.2) ---

_logging(days, commitment) := {
	"access_controls": {"access_logging": {"enabled": true, "includes_failed_attempts": true, "retention_days": days}},
	"soc2": {"commitments": {"log_retention_days": commitment}},
}

test_log_retention_meets_commitment_passes if {
	ac.system_access_monitored with input as _logging(60, 30)
}

test_log_retention_below_commitment_fails if {
	not ac.system_access_monitored with input as _logging(60, 90)
}

test_log_retention_without_commitment_fails_closed if {
	not ac.system_access_monitored with input as json.remove(_logging(365, 30), ["/soc2/commitments"])
}

# --- access-review interval (CC6.2) ---

_reviews(days, commitment) := {
	"access_controls": {"periodic_reviews": {"enabled": true, "documented": true, "frequency_days": days}},
	"soc2": {"commitments": {"access_review_interval_days": commitment}},
}

test_access_review_within_commitment_passes if {
	ac.access_rights_reviewed with input as _reviews(120, 180)
}

test_access_review_over_commitment_fails if {
	not ac.access_rights_reviewed with input as _reviews(120, 90)
}

# --- platform thresholds are commitments too (advisory) ---

test_cluster_admin_limit_is_the_entity_commitment if {
	inp := {
		"openshift": {"rbac": {"enabled": true, "cluster_admin_users_limited": true, "cluster_admin_users": ["a", "b", "c", "d"], "service_accounts_restricted": true}},
		"soc2": {"commitments": {"max_cluster_admins": 5}},
	}
	ac.openshift_rbac_configured with input as inp
	not ac.openshift_rbac_configured with input as json.patch(inp, [{"op": "replace", "path": "/soc2/commitments/max_cluster_admins", "value": 3}])
}

# --- report scoring ---

_all_pass := {c: {"check": true} | some c, _ in main.criteria_checks}

test_all_criteria_pass_with_scope_and_description_is_compliant if {
	r := main.compliance_report with input as {"soc2": {"categories_in_scope": []}}
		with main.criteria_checks as _all_pass
		with main.service_commitments_defined as true
		with main.system_boundaries_defined as true
	r.compliant == true
	r.total_controls == 12
	r.failed_controls == 0
	r.violations == []
}

test_two_failed_checks_fail_one_criterion_once if {
	checks := object.union(_all_pass, {"CC6.1": {"a": false, "b": false, "c": true}})
	r := main.compliance_report with input as {"soc2": {"categories_in_scope": []}}
		with main.criteria_checks as checks
		with main.service_commitments_defined as true
		with main.system_boundaries_defined as true
	r.compliant == false
	r.failed_controls == 1
	r.failed_criteria == ["CC6.1"]
	r.criteria["CC6.1"].failed_checks == ["a", "b"]
	"SOC 2 CC6.1: criterion not met - at least one mapped check failed (criteria[\"CC6.1\"].failed_checks)" in r.violations
	"SOC 2 CC6.1: check a not satisfied" in r.violations
}

test_missing_scope_assesses_all_optional_categories if {
	r := main.compliance_report with input as {}
	r.categories_in_scope == ["availability", "confidentiality", "privacy", "processing_integrity"]
}

test_unknown_scope_category_is_a_finding if {
	r := main.compliance_report with input as {"soc2": {"categories_in_scope": ["availablity"]}}
	"SOC 2 scope: unknown category availablity - the optional categories are availability, confidentiality, processing_integrity, privacy (security is always in scope)" in r.violations
}

test_out_of_scope_category_does_not_block if {
	r := main.compliance_report with input as {"soc2": {"categories_in_scope": ["privacy"]}}
		with main.criteria_checks as _all_pass
		with main.service_commitments_defined as true
		with main.system_boundaries_defined as true
		with main.privacy_compliant as true
		with main.availability_compliant as false
	r.compliant == true
}
