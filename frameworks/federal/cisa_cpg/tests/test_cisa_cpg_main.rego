package cisa_cpg.main_test

import rego.v1

import data.cisa_cpg.main

# ── Contract smoke: report never collapses to {} ─────────────────────────────

test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
	report.compliant == false
	report.violation_count > 0
}

# ── Fully compliant organization ─────────────────────────────────────────────

compliant_input := {
	"entity_name": "Example Utility Coop",
	"assessment_date": "2026-09-02",
	# Shared fact namespaces (same collection feeds nist.csf modules)
	"identify": {"asset_management": {
		"physical_devices_inventoried": true,
		"software_platforms_inventoried": true,
	}},
	"access_control": {"remote_access": {"multi_factor_authentication": true}},
	# CPG-specific namespace
	"cpg": {
		"governance": {
			"responsibilities_established": true,
			"oversight_managed": true,
			"incident_response_plans_managed": true,
			"supply_chain_reporting_required": true,
			"msp_risk_managed": true,
		},
		"identify": {
			"kev_mitigated": true,
			"independent_validation": true,
			"vulnerability_disclosure_process": true,
			"network_topology_documented": true,
		},
		"protect": {
			"default_passwords_changed": true,
			"minimum_password_strength": true,
			"unique_credentials": true,
			"departing_credentials_revoked": true,
			"unsuccessful_logins_monitored": true,
			"separate_privileged_accounts": true,
			"least_privilege": true,
			"network_segmentation": true,
			"cybersecurity_training": true,
			"strong_encryption": true,
			"email_security": true,
			"macros_disabled": true,
			"change_management": true,
			"backups_maintained": true,
			"hw_sw_approval_process": true,
			"log_collection_storage": true,
			"unauthorized_devices_prohibited": true,
			"internet_facing_secured": true,
		},
		"detect": {
			"malicious_code_detection": true,
			"adverse_events_identified": true,
		},
		"respond": {
			"incident_communications": true,
			"incident_reporting": true,
		},
		"recover": {"incident_planning_preparedness": true},
	},
}

test_fully_compliant if {
	report := main.compliance_report with input as compliant_input
	report.compliant == true
	report.violation_count == 0
}

# ── Shared-fact reuse (one collection, two frameworks) ───────────────────────

test_missing_asset_inventory_uses_csf_identify_facts if {
	inp := json.remove(compliant_input, ["identify/asset_management/physical_devices_inventoried"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "CPG 2.A")
}

test_missing_mfa_uses_csf_protect_fact if {
	inp := json.remove(compliant_input, ["access_control"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "CPG 3.F")
}

# ── Targeted goal gaps ───────────────────────────────────────────────────────

test_missing_kev_mitigation_violates if {
	inp := json.remove(compliant_input, ["cpg/identify/kev_mitigated"])
	report := main.compliance_report with input as inp
	some v in report.violations
	contains(v, "CPG 2.B")
}

test_missing_msp_risk_violates if {
	inp := json.remove(compliant_input, ["cpg/governance/msp_risk_managed"])
	report := main.compliance_report with input as inp
	some v in report.violations
	contains(v, "CPG 1.E")
}

test_missing_incident_comms_violates if {
	inp := json.remove(compliant_input, ["cpg/respond/incident_communications"])
	report := main.compliance_report with input as inp
	some v in report.violations
	contains(v, "CPG 5.A")
}

# ── Function rollup ──────────────────────────────────────────────────────────

test_function_summary_counts if {
	inp := json.remove(compliant_input, [
		"cpg/protect/macros_disabled",
		"cpg/protect/email_security",
		"cpg/recover/incident_planning_preparedness",
	])
	report := main.compliance_report with input as inp
	report.function_summary.protect == 2
	report.function_summary.recover == 1
	report.function_summary.govern == 0
	report.violation_count == 3
}
