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

# ── Evidence rule (data-driven): only the boolean true passes a yes/no fact ──
# Every boolean in the all-pass fixture is replaced in turn by a wrong-typed value, by null, and removed.
# Each must fail its control and say why; a boolean false keeps the plain finding.

_evidence_bool_paths := [p | walk(compliant_input, [p, v]); is_boolean(v)]

_evidence_bad_values := ["false", "true", "no", "yes", 0, 1, null, [], {}]

test_evidence_fixture_has_every_boolean_fact if {
	count(_evidence_bool_paths) == 35
	every p in _evidence_bool_paths {
		object.get(compliant_input, p, null) == true
	}
}

test_evidence_wrong_type_or_null_never_passes if {
	every p in _evidence_bool_paths {
		every bad in _evidence_bad_values {
			report := main.compliance_report with input as json.patch(compliant_input, [{"op": "replace", "path": p, "value": bad}])
			report.compliant == false
			report.violation_count == 1
			some v in report.violations
			contains(v, "[evidence ")
			contains(v, concat(".", p))
		}
	}
}

test_evidence_string_names_the_type if {
	every p in _evidence_bool_paths {
		report := main.compliance_report with input as json.patch(compliant_input, [{"op": "replace", "path": p, "value": "false"}])
		some v in report.violations
		contains(v, "is not a boolean (got string)")
	}
}

test_evidence_removed_fact_never_passes if {
	every p in _evidence_bool_paths {
		report := main.compliance_report with input as json.remove(compliant_input, [p])
		report.compliant == false
		report.violation_count == 1
		some v in report.violations
		contains(v, "evidence missing")
		contains(v, "not collected")
	}
}

test_evidence_boolean_false_is_a_plain_finding if {
	every p in _evidence_bool_paths {
		report := main.compliance_report with input as json.patch(compliant_input, [{"op": "replace", "path": p, "value": false}])
		report.compliant == false
		report.violation_count == 1
		some v in report.violations
		not contains(v, "[evidence ")
	}
}

test_evidence_null_or_string_sections_never_pass if {
	every k in {k | some k, section in compliant_input; is_object(section)} {
		every bad in [null, "true", "1", 1, true] {
			report := main.compliance_report with input as object.union(compliant_input, {k: bad})
			report.compliant == false
		}
	}
}

test_evidence_non_object_input_never_passes if {
	every bad in [null, "true", 1, true, []] {
		report := main.compliance_report with input as bad
		report.compliant == false
		report.violation_count >= report.total_controls
	}
}
