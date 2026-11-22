package soc2.criteria_test

import rego.v1

import data.soc2.common_criteria_test as fx
import data.soc2.criteria as cc
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
	cc.common_criteria_ids == _cc_ids
	legacy := {c | some c, _ in main._common_criteria_checks}
	count(legacy) == 12
	every c in legacy {
		c in _cc_ids
	}
}

test_empty_input_scores_all_mapped_criteria_all_failed if {
	r := main.compliance_report with input as {}

	# no scope list: all four optional categories are assessed (33 common + 16 optional criteria)
	r.total_controls == 49
	r.failed_controls == 49
	r.compliant == false
	r.control_result_counts == {"pass": 0, "fail": 0, "not_assessed": 49}
	"SOC 2 CC6.6: Access from outside the system boundary protected - not assessed - evidence missing: input.remote_access.session_timeout.configured, input.remote_access.session_timeout.max_idle_minutes, input.remote_access.vpn_encryption.enabled, input.remote_access.vpn_required, input.soc2.commitments.max_idle_minutes (the entity's stated value) not supplied or not of the expected type" in r.violations
	"SOC 2 CC1.1: Integrity and ethics upheld across the entity - not assessed - no attestation at input.soc2.attestations[\"CC1.1\"]; this organisational criterion is met only by {attested: true, by, date}" in r.violations
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

test_all_criteria_pass_with_scope_and_description_is_compliant if {
	r := main.compliance_report with input as fx.fixture
	r.compliant == true
	r.total_controls == 49
	r.failed_controls == 0
	r.violations == []
	r.control_result_counts == {"pass": 49, "fail": 0, "not_assessed": 0}
	r.basis_counts == {"evidence": 26, "attestation": 23}
	r.coverage.common_criteria_evaluated == 33
}

test_common_criteria_split_ten_evidence_twenty_three_attestation if {
	r := main.compliance_report with input as json.patch(fx.fixture, [{"op": "replace", "path": "/soc2/categories_in_scope", "value": []}])
	r.compliant == true
	r.total_controls == 33
	r.basis_counts == {"evidence": 10, "attestation": 23}
}

# The fact spec reproduces the earlier mapped checks: on the all-pass input every one of them holds.
test_legacy_mapped_checks_agree_with_the_fixture if {
	r := main.compliance_report with input as fx.fixture
	every _, st in r.criteria {
		st.satisfied == true
	}
}

test_two_failed_facts_fail_one_criterion_once if {
	inp := json.patch(fx.fixture, [
		{"op": "replace", "path": "/access_controls/shared_accounts", "value": ["shared-1"]},
		{"op": "replace", "path": "/network_security/firewalls/configured", "value": false},
	])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.failed_controls == 1
	r.failed_criteria == ["CC6.1"]
	"SOC 2 CC6.1: Logical access to protected systems and data controlled - fail - input.access_controls.shared_accounts is a list of 1, required an empty list; input.network_security.firewalls.configured is false, required true" in r.violations
}

# A supplied fact that fails outranks a missing one: the criterion is a fail, and both are reported.
test_fail_outranks_missing_evidence if {
	inp := json.remove(json.patch(fx.fixture, [{"op": "replace", "path": "/remote_access/vpn_required", "value": false}]), ["/remote_access/vpn_encryption"])
	r := main.compliance_report with input as inp
	row := [x | some x in r.control_results; x.id == "CC6.6"][0]
	row.status == "fail"
	count(row.findings) == 2
}

test_missing_commitment_is_not_assessed if {
	inp := json.remove(fx.fixture, ["/soc2/commitments/max_idle_minutes"])
	r := main.compliance_report with input as inp
	row := [x | some x in r.control_results; x.id == "CC6.6"][0]
	row.status == "not_assessed"
	row.reason == "evidence_missing"
}

test_string_where_boolean_belongs_is_not_assessed if {
	inp := json.patch(fx.fixture, [{"op": "replace", "path": "/soc2/change_management/approval/required", "value": "true"}])
	r := main.compliance_report with input as inp
	row := [x | some x in r.control_results; x.id == "CC8.1"][0]
	row.status == "not_assessed"
	r.compliant == false
}

test_unsigned_attestation_fails if {
	inp := json.remove(fx.fixture, ["/soc2/attestations/CC3.3/by"])
	r := main.compliance_report with input as inp
	row := [x | some x in r.control_results; x.id == "CC3.3"][0]
	row.status == "fail"
	row.reason == "fail"
}

test_attestation_true_as_string_fails if {
	inp := json.patch(fx.fixture, [{"op": "replace", "path": "/soc2/attestations/CC5.2/attested", "value": "true"}])
	r := main.compliance_report with input as inp
	row := [x | some x in r.control_results; x.id == "CC5.2"][0]
	row.status == "fail"
}

test_unknown_attestation_key_blocks_compliance if {
	inp := json.patch(fx.fixture, [{"op": "add", "path": "/soc2/attestations/CC10.1", "value": {"attested": true, "by": "x", "date": "2026-11-01"}}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.failed_controls == 0
	"SOC 2 input: attestation key \"CC10.1\" is not a SOC 2 criterion evaluated here" in r.violations
}

test_attestation_for_evidence_criterion_is_not_read if {
	inp := json.patch(fx.fixture, [
		{"op": "add", "path": "/soc2/attestations/CC6.6", "value": {"attested": true, "by": "x", "date": "2026-11-01"}},
		{"op": "replace", "path": "/remote_access/vpn_required", "value": false},
	])
	r := main.compliance_report with input as inp
	r.compliant == false
	"CC6.6" in r.failed_criteria
	"SOC 2 input: attestation key \"CC6.6\" names an evidence-based criterion; it is decided from facts, the attestation is not read" in r.violations
}

test_attestations_not_an_object_is_a_finding if {
	inp := json.patch(fx.fixture, [{"op": "replace", "path": "/soc2/attestations", "value": ["CC1.1"]}])
	r := main.compliance_report with input as inp
	r.compliant == false
	"SOC 2 input: input.soc2.attestations is not an object; no attestation can be read" in r.violations
}

test_status_values_are_pass_fail_not_assessed if {
	r1 := main.compliance_report with input as {}
	r2 := main.compliance_report with input as fx.fixture
	inp := json.patch(fx.fixture, [{"op": "replace", "path": "/soc2/attestations/CC1.1/attested", "value": false}])
	r3 := main.compliance_report with input as inp
	every r in [r1, r2, r3] {
		every row in r.control_results {
			row.status in {"pass", "fail", "not_assessed"}
		}
	}
}

test_control_results_in_natural_order if {
	r := main.compliance_report with input as {}
	ids := [row.id | some row in r.control_results]
	ids[0] == "CC1.1"
	ids[32] == "CC9.2"
	ids[33] == "A1.1"
	ids[48] == "P7.1"
}

test_titles_are_short if {
	every _, c in cc.criteria {
		count(c.title) <= 100
	}
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
	inp := json.remove(json.patch(fx.fixture, [{"op": "replace", "path": "/soc2/categories_in_scope", "value": ["privacy"]}]), ["/backup"])
	r := main.compliance_report with input as inp
	r.compliant == true
	r.total_controls == 42
}

# --- optional categories (follow-up 2026-11-17) ---

_optional_ids := {
	"A1.1", "A1.2", "A1.3", "C1.1", "C1.2", "PI1.1", "PI1.2", "PI1.3", "PI1.4", "PI1.5", "P1.1", "P2.1",
	"P3.1", "P3.2", "P4.1", "P4.2", "P4.3", "P5.1", "P5.2", "P6.1", "P6.2", "P6.3", "P6.4", "P6.5",
	"P6.6", "P6.7", "P7.1", "P8.1",
}

test_optional_criteria_ids_are_real_tsc_ids if {
	count(_optional_ids) == 28
	every crits in main._optional_criteria_checks {
		every c, _ in crits {
			c in _optional_ids
		}
	}
}

test_only_in_scope_categories_add_criteria if {
	r := main.compliance_report with input as {"soc2": {"categories_in_scope": ["availability"]}}
	r.total_controls == 36
	r.categories_in_scope == ["availability"]
	r2 := main.compliance_report with input as {"soc2": {"categories_in_scope": []}}
	r2.total_controls == 33
}

test_category_module_verdict_does_not_decide_compliance if {
	inp := json.patch(fx.fixture, [{"op": "replace", "path": "/soc2/categories_in_scope", "value": ["availability"]}])
	r := main.compliance_report with input as inp
		with main.availability_compliant as false
	r.compliant == true
	r.advisory.categories.availability == false
}

_backup(retention, commit_ret, test_days, commit_test) := {
	"backup": {"automated_backups": {"enabled": true}, "offsite_storage": {"enabled": true}, "retention": {"days": retention}, "recovery_testing": {"frequency_days": test_days}},
	"soc2": {"commitments": {"backup_retention_days": commit_ret, "recovery_test_interval_days": commit_test}},
}

test_a1_2_and_a1_3_use_the_entity_commitments if {
	main.backup_recovery_infrastructure with input as _backup(14, 14, 180, 180)
	main.recovery_plan_tested with input as _backup(14, 14, 180, 180)
	not main.backup_recovery_infrastructure with input as _backup(14, 30, 180, 180)
	not main.recovery_plan_tested with input as _backup(14, 14, 180, 90)
}

test_a1_commitments_missing_fail_closed if {
	inp := json.remove(_backup(14, 14, 180, 180), ["/soc2/commitments"])
	not main.backup_recovery_infrastructure with input as inp
	not main.recovery_plan_tested with input as inp
	f := main.category_evidence_findings with input as inp
	"A1.3: evidence missing - input.soc2.commitments.recovery_test_interval_days (the entity's stated value) not supplied or not a number" in f
	not main.recovery_plan_tested with input as json.patch(_backup(14, 14, 180, 180), [{"op": "replace", "path": "/backup/recovery_testing/frequency_days", "value": null}])
}

_breach(auth, ind, c_auth, c_ind) := {
	"privacy": {"breach_notification": {"procedures_documented": true, "timeline_compliance": {"authorities": auth, "individuals": ind}}},
	"soc2": {"commitments": {"breach_notice_hours_authorities": c_auth, "breach_notice_hours_individuals": c_ind}},
}

test_p6_6_breach_notice_against_commitment_not_72_hours if {
	main.breach_notification_within_commitments with input as _breach(96, 120, 96, 120)
	not main.breach_notification_within_commitments with input as _breach(96, 120, 48, 120)
	not main.breach_notification_within_commitments with input as json.remove(_breach(24, 24, 72, 72), ["/soc2/commitments"])
}

test_in_scope_criterion_failure_is_reported_by_id if {
	r := main.compliance_report with input as {"soc2": {"categories_in_scope": ["availability"]}}
	r.compliant == false
	"A1.3" in r.failed_criteria
	"SOC 2 A1.3: Recovery testing carried out - not assessed - evidence missing: input.backup.recovery_testing.frequency_days, input.soc2.commitments.recovery_test_interval_days (the entity's stated value) not supplied or not of the expected type" in r.violations
}
