package nis2.main_test

import data.nis2.main
import rego.v1

test_compliance_report_defined_on_empty_input if {
	r := main.compliance_report with input as {}
	r.framework == "EU Network and Information Security Directive 2 (NIS2)"
	is_number(r.total_controls)

	# empty input must fail closed: the report carries the violations that make it non-compliant
	r.compliant == false
	count(r.violations) == r.violation_count
	count(r.violations) > 0
}

test_non_compliant_on_empty_input if {
	not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
	count(main.violations) > 20 with input as {}
}

test_defaults_for_metadata if {
	r := main.compliance_report with input as {}
	r.entity_name == "unknown"
	r.sector == "unknown"
	r.assessed_at == "unknown"
}

test_metadata_picked_up_from_input if {
	r := main.compliance_report with input as {
		"entity_name": "Big Bank Plc",
		"entity_type": "credit_institution",
		"sector": "banking",
		"entity_category": "essential",
		"assessment_date": "2026-06-26",
	}
	r.entity_name == "Big Bank Plc"
	r.sector == "banking"
	r.assessed_at == "2026-06-26"
}

# Semantic review 2026-11-13: total_controls must cover every violation rule.
# Every control fails on empty input, so the violation count there is the number of controls implemented.
test_empty_input_fails_every_control if {
	r := main.compliance_report with input as {}
	r.total_controls == 37
	r.violation_count == 37
	r.failed_controls == 37
	r.passed_controls == 0
	r.not_appropriate_controls == 0
}

# ── Fixtures ─────────────────────────────────────────────────────────────────

full := {
	"risk_management": {
		"risk_analysis": {"documented": true},
		"security_policies": {"approved_by_management": true},
		"risk_review": {"frequency_annual": true},
	},
	"incident_handling": {
		"plan": {"documented": true},
		"significant_incident": {"early_warning_24h": true, "notification_72h": true, "final_report_1month": true},
		"log_retention": {"period_defined": true},
	},
	"business_continuity": {
		"bcp": {"documented": true, "tested_annually": true},
		"drp": {"documented": true},
		"crisis_management": {"plan_exists": true},
	},
	"supply_chain": {
		"vendor_assessment": {"process_exists": true},
		"critical_suppliers": {"identified": true},
		"contractual_requirements": {"security_clauses": true},
	},
	"secure_development": {
		"sdlc_policy": {"documented": true},
		"vulnerability_management": {"process_exists": true},
		"patch_management": {"timely": true},
	},
	"effectiveness_assessment": {"penetration_testing": {"annual": true}, "audit": {"regular": true}},
	"training": {
		"cybersecurity_awareness": {"conducted_annually": true},
		"management_body": {"cybersecurity_training": true},
	},
	"cyber_hygiene": {"patch_policy": {"exists": true}},
	"cryptography": {
		"policy": {"documented": true},
		"encryption": {"sensitive_data_at_rest": true, "data_in_transit": true},
	},
	"access_control": {
		"principle_of_least_privilege": {"enforced": true},
		"privileged_accounts": {"managed": true},
	},
	"asset_management": {"inventory": {"maintained": true}},
	"hr_security": {"joiners_movers_leavers": {"process_exists": true}},
	"mfa": {
		"remote_access": {"enforced": true},
		"privileged_accounts": {"enforced": true},
		"critical_systems": {"enforced": true},
	},
	"secure_communications": {"voice_video_text": {"secured": true}, "emergency_systems": {"secured": true}},
	"governance": {"management_body": {"approved_measures": true, "oversight_accountability": true}},
}

_invalid_statements := [
	{"appropriate": false},
	{"appropriate": false, "justification": "   "},
	{"appropriate": false, "justification": null},
	{"appropriate": "false", "justification": "string, not a boolean"},
	{"appropriate": null, "justification": "null is not a statement"},
	{"appropriate": true, "justification": "appropriate, so no exemption"},
	{"justification": "no appropriate field"},
	"not appropriate",
]

_j(inp) := {v | some v in main.violations with input as inp; contains(v, "Art.21(2)(j)")}

_counts_add_up(r) if (r.passed_controls + r.failed_controls) + r.not_appropriate_controls == r.total_controls

test_full_input_is_compliant if {
	r := main.compliance_report with input as full
	r.compliant == true
	r.violation_count == 0
	r.passed_controls == 37
	_counts_add_up(r)
}

# ── Article 21(2)(j): MFA or continuous authentication ──────────────────────

test_continuous_authentication_satisfies_strong_authentication if {
	inp := json.patch(full, [
		{"op": "remove", "path": "/mfa"},
		{"op": "add", "path": "/continuous_authentication", "value": {
			"remote_access": {"enforced": true},
			"privileged_accounts": {"enforced": true},
			"critical_systems": {"enforced": true},
		}},
	])
	count(_j(inp)) == 0
	main.compliant with input as inp
}

test_neither_alternative_is_a_finding_per_scope if {
	inp := json.patch(full, [{"op": "replace", "path": "/mfa/privileged_accounts/enforced", "value": false}])
	found := _j(inp)
	count(found) == 1
	some v in found
	contains(v, "privileged accounts")
}

test_mixed_alternatives_across_scopes_pass if {
	inp := json.patch(full, [
		{"op": "replace", "path": "/mfa/critical_systems/enforced", "value": false},
		{"op": "add", "path": "/continuous_authentication", "value": {"critical_systems": {"enforced": true}}},
	])
	count(_j(inp)) == 0
}

# ── Article 21(2)(j): the communications limbs ──────────────────────────────

test_unsecured_communications_is_a_finding if {
	inp := json.patch(full, [{"op": "replace", "path": "/secure_communications/voice_video_text/secured", "value": false}])
	found := _j(inp)
	count(found) == 1
	some v in found
	contains(v, "Voice, video and text")
}

test_missing_emergency_communications_evidence_is_a_finding if {
	inp := json.patch(full, [{"op": "remove", "path": "/secure_communications/emergency_systems"}])
	found := _j(inp)
	count(found) == 1
	some v in found
	contains(v, "emergency communication")
}

test_mfa_alone_does_not_cover_article_21_2_j if {
	inp := json.patch(full, [{"op": "remove", "path": "/secure_communications"}])
	count(_j(inp)) == 2
	not main.compliant with input as inp
}

# ── "where appropriate": only an explicit, typed, justified statement exempts ─

test_stated_not_appropriate_with_justification_is_not_a_finding if {
	inp := json.patch(full, [
		{"op": "remove", "path": "/secure_communications/emergency_systems"},
		{"op": "add", "path": "/applicability", "value": {"secured_emergency_communications": {
			"appropriate": false,
			"justification": "Single-site entity; emergency coordination uses the public safety network",
		}}},
	])
	r := main.compliance_report with input as inp
	r.compliant == true
	r.not_appropriate_controls == 1
	r.passed_controls == 36
	r.measures_not_appropriate.secured_emergency_communications == "Single-site entity; emergency coordination uses the public safety network"
	_counts_add_up(r)
}

test_statement_without_justification_does_not_exempt if {
	failing := [statement |
		some statement in _invalid_statements
		inp := json.patch(full, [
			{"op": "remove", "path": "/secure_communications/emergency_systems"},
			{"op": "add", "path": "/applicability", "value": {"secured_emergency_communications": statement}},
		])
		r := main.compliance_report with input as inp
		r.compliant == false
		r.not_appropriate_controls == 0
		r.failed_controls == 1
	]
	count(failing) == count(_invalid_statements)
}

test_invalid_statement_does_not_exempt_strong_authentication if {
	rejected := [statement |
		some statement in _invalid_statements
		inp := json.patch(full, [
			{"op": "remove", "path": "/mfa/remote_access"},
			{"op": "add", "path": "/applicability", "value": {"strong_authentication_remote_access": statement}},
		])
		count(_j(inp)) == 1
	]
	count(rejected) == count(_invalid_statements)
}

test_statement_is_ignored_when_the_measure_is_in_place if {
	inp := json.patch(full, [{"op": "add", "path": "/applicability", "value": {"strong_authentication_remote_access": {
		"appropriate": false,
		"justification": "left over from an earlier assessment",
	}}}])
	r := main.compliance_report with input as inp
	r.not_appropriate_controls == 0
	r.passed_controls == 37
}

test_statement_does_not_exempt_measures_outside_the_where_appropriate_set if {
	inp := json.patch(full, [
		{"op": "remove", "path": "/incident_handling/plan"},
		{"op": "add", "path": "/applicability", "value": {"incident_handling": {"appropriate": false, "justification": "n/a"}}},
	])
	r := main.compliance_report with input as inp
	r.failed_controls == 1
	r.not_appropriate_controls == 0
}

# Article 21(2)(h): "... and, where appropriate, encryption".
test_encryption_not_appropriate_needs_the_statement if {
	without := json.patch(full, [{"op": "replace", "path": "/cryptography/encryption/sensitive_data_at_rest", "value": false}])
	not main.compliant with input as without

	with_statement := json.patch(without, [{"op": "add", "path": "/applicability", "value": {"encryption_at_rest": {
		"appropriate": false,
		"justification": "No sensitive data is stored; the system is a stateless relay",
	}}}])
	main.compliant with input as with_statement
}

test_cryptography_policy_itself_is_not_where_appropriate if {
	inp := json.patch(full, [
		{"op": "remove", "path": "/cryptography/policy"},
		{"op": "add", "path": "/applicability", "value": {"cryptography_policy": {"appropriate": false, "justification": "n/a"}}},
	])
	not main.compliant with input as inp
}

# ── Evidence typing ─────────────────────────────────────────────────────────

test_non_boolean_mfa_evidence_is_a_finding if {
	values := ["yes", "true", "no", 1, null, {"enforced": true}, [true]]
	rejected := [bad |
		some bad in values
		inp := json.patch(full, [{"op": "replace", "path": "/mfa/remote_access/enforced", "value": bad}])
		count(_j(inp)) == 1
	]
	count(rejected) == count(values)
}

test_every_non_boolean_value_is_rejected if {
	rejected := [bad |
		some bad in ["yes", "true", "no", 1, null, {"documented": true}, [true]]
		inp := json.patch(full, [{"op": "replace", "path": "/risk_management/risk_analysis/documented", "value": bad}])
		r := main.compliance_report with input as inp
		r.failed_controls == 1
	]
	count(rejected) == 7
}

test_null_section_fails_its_controls if {
	inp := json.patch(full, [{"op": "replace", "path": "/business_continuity", "value": null}])
	r := main.compliance_report with input as inp
	r.failed_controls == 4
	count(r.article_summary.art_21c_continuity) == 4
	_counts_add_up(r)
}

# ── Citations (Directive (EU) 2022/2555) ────────────────────────────────────

_only_violation(path) := v if {
	# regal ignore:external-reference
	inp := json.patch(full, [{"op": "remove", "path": path}])

	# regal ignore:external-reference
	found := main.violations with input as inp
	count(found) == 1
	some v in found
}

test_management_training_cites_article_20_2 if {
	v := _only_violation("/training/management_body")
	startswith(v, "NIS2 Art.20(2):")
	r := main.compliance_report with input as json.patch(full, [{"op": "remove", "path": "/training/management_body"}])
	count(r.article_summary.art_20_governance) == 1
	count(r.article_summary.art_21g_hygiene_training) == 0
}

test_management_approval_and_oversight_cite_article_20_1 if {
	startswith(_only_violation("/governance/management_body/approved_measures"), "NIS2 Art.20(1):")
	startswith(_only_violation("/governance/management_body/oversight_accountability"), "NIS2 Art.20(1):")
}

test_reporting_deadlines_cite_article_23_4 if {
	startswith(_only_violation("/incident_handling/significant_incident/early_warning_24h"), "NIS2 Art.23(4)(a):")
	startswith(_only_violation("/incident_handling/significant_incident/notification_72h"), "NIS2 Art.23(4)(b):")
	startswith(_only_violation("/incident_handling/significant_incident/final_report_1month"), "NIS2 Art.23(4)(d):")
}

# The Directive sets no log retention period; the check is a defined period and does not claim one year.
test_log_retention_is_a_defined_period_not_one_year if {
	v := _only_violation("/incident_handling/log_retention")
	startswith(v, "NIS2 Art.21(2)(b):")
	not contains(v, "1 year")
	contains(v, "library criterion")
}

test_legacy_one_year_field_still_counts_as_a_defined_period if {
	inp := json.patch(full, [{"op": "replace", "path": "/incident_handling/log_retention", "value": {"minimum_1_year": true}}])
	main.compliant with input as inp
}

test_all_frequency_criteria_are_labelled if {
	labelled := [path |
		some path in [
			"/risk_management/risk_review",
			"/business_continuity/bcp/tested_annually",
			"/effectiveness_assessment/penetration_testing",
			"/training/cybersecurity_awareness",
		]
		contains(_only_violation(path), "library criterion")
	]
	count(labelled) == 4
}

# Every single-control removal produces exactly one violation and keeps the counts adding up.
test_counts_add_up_for_every_single_failure if {
	paths := [
		"/risk_management/risk_analysis", "/incident_handling/plan", "/business_continuity/drp",
		"/supply_chain/critical_suppliers", "/secure_development/patch_management",
		"/effectiveness_assessment/audit", "/cyber_hygiene", "/cryptography/policy",
		"/asset_management", "/mfa/critical_systems", "/secure_communications/voice_video_text",
		"/governance/management_body/approved_measures",
	]
	ok := [path |
		some path in paths
		r := main.compliance_report with input as json.patch(full, [{"op": "remove", "path": path}])
		r.failed_controls == 1
		r.passed_controls == 36
		_counts_add_up(r)
	]
	count(ok) == count(paths)
}
