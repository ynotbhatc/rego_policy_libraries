package nist_ssdf.main_test

import rego.v1

import data.nist_ssdf.main

# A fully-hardened SDLC posture — every discrete check passes.
compliant_input := {
	"organization": {
		"security_requirements_defined": true, "third_party_requirements_communicated": true,
		"requirements_maintained": true, "roles_defined": true, "role_training_provided": true,
		"management_commitment": true, "security_criteria_defined": true,
	},
	"toolchain": {
		"specified": true, "security_integrated": true, "artifacts_collected": true,
		"security_check_data_collected": true,
	},
	"environments": {"separated": true, "endpoints_secured": true},
	"source_control": {"access_controlled": true, "branch_protection": true, "change_tracking": true},
	"provenance": {"integrity_verification": true, "artifacts_signed": true},
	"release_management": {"releases_archived": true, "sbom_generated": true, "provenance_recorded": true},
	"design": {"threat_model_performed": true, "security_requirements_tracked": true, "design_review_performed": true},
	"dependencies": {"vetted_components": true, "sca_enabled": true, "vulnerability_scanned": true},
	"coding": {"secure_coding_standards": true},
	"build": {"hardening_flags": true, "integrity_verified": true},
	"code_review": {"peer_review_required": true},
	"sast": {"enabled": true},
	"testing": {"security_testing_planned": true, "dast_enabled": true},
	"configuration": {"secure_defaults": true, "defaults_verified": true},
	"vulnerability_management": {
		"monitoring_enabled": true, "disclosure_program": true, "response_process": true,
		"triage_process": true, "remediation_sla_defined": true, "root_cause_analysis": true,
		"systemic_review": true, "process_improvement": true,
	},
}

# ── Fully-compliant posture ───────────────────────────────────────────────────

test_fully_compliant_is_compliant if {
	main.compliant with input as compliant_input
}

test_fully_compliant_scores_100 if {
	main.compliance_percentage == 100 with input as compliant_input
}

test_fully_compliant_has_41_controls if {
	main.total_controls == 41 with input as compliant_input
}

test_fully_compliant_no_violations if {
	count(main.all_violations) == 0 with input as compliant_input
}

# ── Empty input must NOT collapse to null (loud failure, low score) ────────────

test_empty_input_is_noncompliant if {
	not main.compliant with input as {}
}

test_empty_input_reports_all_failing if {
	main.compliance_percentage == 0 with input as {}
}

test_empty_input_report_is_defined if {
	# report must resolve (not undefined/null) even with no facts
	is_object(main.compliance_report) with input as {}
}

# ── A single missing control fails exactly one check ──────────────────────────

test_single_gap_fails_one_control if {
	gapped := object.union(compliant_input, {"sast": {"enabled": false}})
	count(main.all_violations) == 1 with input as gapped
}

test_single_gap_flags_pw_7_2 if {
	gapped := object.union(compliant_input, {"sast": {"enabled": false}})
	viols := main.all_violations with input as gapped
	viols == ["PW.7.2: Automated static analysis (SAST) is not enabled in the pipeline"]
}

# ── Per-group reports resolve ─────────────────────────────────────────────────

test_practice_groups_present if {
	report := main.compliance_report with input as compliant_input
	count(report.practice_groups) == 4
}
