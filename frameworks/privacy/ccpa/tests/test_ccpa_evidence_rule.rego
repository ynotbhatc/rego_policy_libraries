package ccpa.evidence_rule_test

import rego.v1

# Evidence rule (weekly audit 2026-11-24): only the boolean true passes a yes/no fact. Missing, null and
# wrongly typed values ("true", "false", "no", 0, 1) fail the control and the finding names the problem.
# Data-driven: one all-pass fixture per module, every leaf mutated.

fixtures := {
	"admt": {
		"ccpa": {
			"admt": {
				"access": {
					"aggregate_only_when_more_than_four_uses_in_12_months": true,
					"aggregate_responses_used": true,
					"denials_explained": true,
					"easy_methods_no_dark_patterns": true,
					"logic_explained": true,
					"non_retaliation_and_rights_instructions": true,
					"outcome_and_human_role_explained": true,
					"secure_transmission": true,
					"service_provider_assistance": true,
					"specific_purpose_explained": true,
					"verification_per_article_5": true,
				},
				"opt_out": {
					"authorized_agents_accepted": true,
					"ceases_within_15_business_days": true,
					"confirmation_provided": true,
					"easy_minimal_steps_no_dark_patterns": true,
					"fraud_denials_explained": true,
					"no_account_or_extra_information_required": true,
					"no_retaliation": true,
					"no_verification_required": true,
					"not_cookie_banner_only": true,
					"offered": true,
					"online_form_via_named_link": true,
					"pre_processing_opt_out_honored": true,
					"service_providers_notified": true,
					"single_opt_out_of_all_offered": true,
					"twelve_month_wait_before_reconsent": true,
					"two_or_more_methods": true,
				},
				"pre_use_notice": {
					"access_right_and_method_described": true,
					"at_or_before_collection": true,
					"how_it_works_explained": true,
					"in_primary_interaction_manner": true,
					"non_retaliation_stated": true,
					"opt_out_right_and_method_described": true,
					"provided": true,
					"specific_purpose_stated": true,
				},
				"uses_admt_for_significant_decisions": true,
			},
		},
	},
	"business_obligations": {
		"ccpa": {
			"business_obligations": {
				"data_broker": {
					"applicable": true,
					"registered_with_cppa": true,
				},
				"notice_at_collection": {
					"categories_and_purposes_disclosed": true,
					"provided_at_or_before_collection": true,
					"retention_periods_disclosed": true,
					"sale_sharing_disclosed_with_opt_out": true,
				},
				"privacy_policy": {
					"ccpa_rights_disclosure_included": true,
					"contact_information_included": true,
					"lists_categories_collected": true,
					"lists_collection_purposes": true,
					"lists_third_party_categories": true,
					"published_and_updated_annually": true,
				},
				"record_keeping": {
					"annual_metrics_reported": true,
					"requests_retained_24_months": true,
				},
				"service_provider_contracts": {
					"prohibition_on_selling": true,
					"subprocessor_restrictions": true,
					"written_contracts_limiting_use": true,
				},
				"training": {
					"personnel_trained": true,
					"training_documented_and_refreshed": true,
				},
			},
		},
	},
	"consumer_rights": {
		"ccpa": {
			"consumer_rights": {
				"non_discrimination": {
					"no_different_pricing_for_opt_out": true,
					"no_penalty_for_rights_exercise": true,
				},
				"right_to_correct": {
					"correction_process_defined": true,
					"correction_propagated": true,
					"response_within_45_days": true,
				},
				"right_to_delete": {
					"confirmation_provided": true,
					"deletion_process_established": true,
					"deletion_propagated": true,
					"exceptions_documented": true,
				},
				"right_to_know": {
					"categories_disclosed": true,
					"identity_verification_established": true,
					"response_within_45_days": true,
					"specific_pieces_provided": true,
					"two_requests_per_year_honored": true,
				},
				"right_to_limit_sensitive": {
					"honored_within_15_business_days": true,
					"limit_sensitive_pi_link_available": true,
					"use_limited_when_requested": true,
				},
				"right_to_opt_out": {
					"do_not_sell_link_on_homepage": true,
					"gpc_signal_honored": true,
					"honored_within_15_business_days": true,
					"no_reenrollment_within_12_months": true,
				},
			},
		},
	},
	"cybersecurity_audits": {
		"ccpa": {
			"cybersecurity_audits": {
				"audit": {
					"completed": true,
					"covers_required_period": true,
				},
				"auditor": {
					"all_requested_information_provided": true,
					"documents_retained_five_years": true,
					"facts_disclosed_in_good_faith": true,
					"findings_rely_on_evidence_not_management_attestation": true,
					"internal": true,
					"no_participation_in_assessed_activities": true,
					"objective_and_independent": true,
					"qualified": true,
					"report_delivered_to_responsible_executive": true,
					"reports_to_executive_without_cyber_responsibility": true,
					"uses_accepted_standards": true,
				},
				"certification": {
					"includes_required_contents": true,
					"submitted_by_april_1": true,
					"submitted_by_responsible_executive": true,
					"submitted_to_agency": true,
				},
				"components": {
					"assessed": {
						"c01_authentication": true,
						"c02_encryption": true,
						"c03_account_management_access_control": true,
						"c04_inventory": true,
						"c05_secure_configuration": true,
						"c06_vulnerability_scans_pentest_disclosure": true,
						"c07_audit_log_management": true,
						"c08_network_monitoring_defenses": true,
						"c09_antivirus_antimalware": true,
						"c10_segmentation": true,
						"c11_ports_services_protocols": true,
						"c12_cybersecurity_awareness": true,
						"c13_education_training": true,
						"c14_secure_development": true,
						"c15_service_provider_oversight": true,
						"c16_retention_and_disposal": true,
						"c17_incident_response": true,
						"c18_bcdr_backups": true,
					},
					"implementation_and_enforcement_assessed": true,
					"program_documentation_assessed": true,
				},
				"report": {
					"describes_gaps_and_weaknesses": true,
					"describes_information_system": true,
					"documents_remediation_plan_with_timeframe": true,
					"identifies_components_and_effectiveness": true,
					"identifies_corrections_to_prior_reports": true,
					"includes_breach_notifications_if_any": true,
					"names_auditor_and_qualifications": true,
					"names_responsible_individuals": true,
					"signed_independence_statement": true,
				},
				"revenue_tier": "over_100m",
			},
		},
	},
	"data_practices": {
		"ccpa": {
			"data_practices": {
				"data_minimization": {
					"collected_only_for_disclosed_purposes": true,
					"collection_limited_to_necessary": true,
					"not_used_incompatibly": true,
				},
				"data_protection_assessments": {
					"conducted_for_high_risk": true,
					"reviewed_annually": true,
					"submitted_to_cppa_on_request": true,
				},
				"purpose_limitation": {
					"not_sold_beyond_disclosed_categories": true,
					"not_used_beyond_disclosed_purposes": true,
				},
				"retention_limitation": {
					"automated_deletion_enforced": true,
					"not_retained_longer_than_necessary": true,
					"schedule_established_and_documented": true,
				},
				"security": {
					"breach_notification_within_72_hours": true,
					"consumer_notification_without_unreasonable_delay": true,
					"reasonable_security_implemented": true,
				},
			},
		},
	},
	"risk_assessments": {
		"ccpa": {
			"risk_assessments": {
				"activities": {
					"admt_significant_decision": {
						"assessment_completed_before_processing": true,
						"in_use": true,
					},
					"inference_from_observation_work_or_education": {
						"assessment_completed_before_processing": true,
						"in_use": true,
					},
					"inference_in_sensitive_location": {
						"assessment_completed_before_processing": true,
						"in_use": true,
					},
					"selling_or_sharing": {
						"assessment_completed_before_processing": true,
						"in_use": true,
					},
					"sensitive_personal_information": {
						"assessment_completed_before_processing": true,
						"in_use": true,
					},
					"training_admt_or_biometric_technology": {
						"assessment_completed_before_processing": true,
						"in_use": true,
					},
				},
				"admt_provider": {
					"facts_provided_for_recipient_assessments": true,
					"provides_admt_to_recipient_businesses": true,
				},
				"report": {
					"admt_logic_and_output_documented": true,
					"benefits_specific": true,
					"categories_and_minimum_pi_identified": true,
					"contributors_identified": true,
					"decision_to_initiate_documented": true,
					"negative_impacts_with_sources": true,
					"operational_elements_documented": true,
					"purpose_specific_not_generic": true,
					"reviewed_and_approved_by_decision_authority": true,
					"safeguards_documented": true,
				},
				"stakeholders": {
					"processing_employees_included": true,
				},
				"submission": {
					"includes_required_contents": true,
					"reports_available_within_30_days_of_request": true,
					"submitted_by_april_1": true,
					"submitted_by_responsible_executive": true,
				},
				"timing": {
					"legacy_assessment_scheduled": true,
					"legacy_processing_assessed": true,
					"legacy_processing_continuing": true,
					"retained_five_years_or_duration_of_processing": true,
					"reviewed_at_least_every_three_years": true,
					"updated_within_45_days_of_material_change": true,
				},
			},
		},
	},
	"sensitive_data": {
		"ccpa": {
			"sensitive_data": {
				"account_credentials": {
					"not_stored_in_plaintext": true,
				},
				"automated_decisions": {
					"logic_explanation_available": true,
					"opt_out_available": true,
				},
				"biometric_data": {
					"consent_obtained": true,
					"retention_limited": true,
				},
				"genetic_data": {
					"access_controls_implemented": true,
					"not_sold": true,
				},
				"government_ids": {
					"access_limited_and_encrypted": true,
				},
				"health_information": {
					"hipaa_aligned_controls": true,
				},
				"mail_email_text": {
					"not_accessed_except_for_delivery": true,
				},
				"precise_geolocation": {
					"explicit_purpose_limitation": true,
				},
				"racial_ethnic_origin": {
					"dpias_conducted": true,
				},
				"religious_beliefs": {
					"collection_minimized": true,
				},
				"sex_life_orientation": {
					"not_collected_unless_necessary": true,
				},
				"union_membership": {
					"collection_minimized": true,
				},
			},
		},
	},
}

all_pass_input := {
	"ccpa": {
		"admt": {
			"access": {
				"aggregate_only_when_more_than_four_uses_in_12_months": true,
				"aggregate_responses_used": true,
				"denials_explained": true,
				"easy_methods_no_dark_patterns": true,
				"logic_explained": true,
				"non_retaliation_and_rights_instructions": true,
				"outcome_and_human_role_explained": true,
				"secure_transmission": true,
				"service_provider_assistance": true,
				"specific_purpose_explained": true,
				"verification_per_article_5": true,
			},
			"opt_out": {
				"authorized_agents_accepted": true,
				"ceases_within_15_business_days": true,
				"confirmation_provided": true,
				"easy_minimal_steps_no_dark_patterns": true,
				"fraud_denials_explained": true,
				"no_account_or_extra_information_required": true,
				"no_retaliation": true,
				"no_verification_required": true,
				"not_cookie_banner_only": true,
				"offered": true,
				"online_form_via_named_link": true,
				"pre_processing_opt_out_honored": true,
				"service_providers_notified": true,
				"single_opt_out_of_all_offered": true,
				"twelve_month_wait_before_reconsent": true,
				"two_or_more_methods": true,
			},
			"pre_use_notice": {
				"access_right_and_method_described": true,
				"at_or_before_collection": true,
				"how_it_works_explained": true,
				"in_primary_interaction_manner": true,
				"non_retaliation_stated": true,
				"opt_out_right_and_method_described": true,
				"provided": true,
				"specific_purpose_stated": true,
			},
			"uses_admt_for_significant_decisions": true,
		},
		"business_obligations": {
			"data_broker": {
				"applicable": true,
				"registered_with_cppa": true,
			},
			"notice_at_collection": {
				"categories_and_purposes_disclosed": true,
				"provided_at_or_before_collection": true,
				"retention_periods_disclosed": true,
				"sale_sharing_disclosed_with_opt_out": true,
			},
			"privacy_policy": {
				"ccpa_rights_disclosure_included": true,
				"contact_information_included": true,
				"lists_categories_collected": true,
				"lists_collection_purposes": true,
				"lists_third_party_categories": true,
				"published_and_updated_annually": true,
			},
			"record_keeping": {
				"annual_metrics_reported": true,
				"requests_retained_24_months": true,
			},
			"service_provider_contracts": {
				"prohibition_on_selling": true,
				"subprocessor_restrictions": true,
				"written_contracts_limiting_use": true,
			},
			"training": {
				"personnel_trained": true,
				"training_documented_and_refreshed": true,
			},
		},
		"consumer_rights": {
			"non_discrimination": {
				"no_different_pricing_for_opt_out": true,
				"no_penalty_for_rights_exercise": true,
			},
			"right_to_correct": {
				"correction_process_defined": true,
				"correction_propagated": true,
				"response_within_45_days": true,
			},
			"right_to_delete": {
				"confirmation_provided": true,
				"deletion_process_established": true,
				"deletion_propagated": true,
				"exceptions_documented": true,
			},
			"right_to_know": {
				"categories_disclosed": true,
				"identity_verification_established": true,
				"response_within_45_days": true,
				"specific_pieces_provided": true,
				"two_requests_per_year_honored": true,
			},
			"right_to_limit_sensitive": {
				"honored_within_15_business_days": true,
				"limit_sensitive_pi_link_available": true,
				"use_limited_when_requested": true,
			},
			"right_to_opt_out": {
				"do_not_sell_link_on_homepage": true,
				"gpc_signal_honored": true,
				"honored_within_15_business_days": true,
				"no_reenrollment_within_12_months": true,
			},
		},
		"cybersecurity_audits": {
			"audit": {
				"completed": true,
				"covers_required_period": true,
			},
			"auditor": {
				"all_requested_information_provided": true,
				"documents_retained_five_years": true,
				"facts_disclosed_in_good_faith": true,
				"findings_rely_on_evidence_not_management_attestation": true,
				"internal": true,
				"no_participation_in_assessed_activities": true,
				"objective_and_independent": true,
				"qualified": true,
				"report_delivered_to_responsible_executive": true,
				"reports_to_executive_without_cyber_responsibility": true,
				"uses_accepted_standards": true,
			},
			"certification": {
				"includes_required_contents": true,
				"submitted_by_april_1": true,
				"submitted_by_responsible_executive": true,
				"submitted_to_agency": true,
			},
			"components": {
				"assessed": {
					"c01_authentication": true,
					"c02_encryption": true,
					"c03_account_management_access_control": true,
					"c04_inventory": true,
					"c05_secure_configuration": true,
					"c06_vulnerability_scans_pentest_disclosure": true,
					"c07_audit_log_management": true,
					"c08_network_monitoring_defenses": true,
					"c09_antivirus_antimalware": true,
					"c10_segmentation": true,
					"c11_ports_services_protocols": true,
					"c12_cybersecurity_awareness": true,
					"c13_education_training": true,
					"c14_secure_development": true,
					"c15_service_provider_oversight": true,
					"c16_retention_and_disposal": true,
					"c17_incident_response": true,
					"c18_bcdr_backups": true,
				},
				"implementation_and_enforcement_assessed": true,
				"program_documentation_assessed": true,
			},
			"report": {
				"describes_gaps_and_weaknesses": true,
				"describes_information_system": true,
				"documents_remediation_plan_with_timeframe": true,
				"identifies_components_and_effectiveness": true,
				"identifies_corrections_to_prior_reports": true,
				"includes_breach_notifications_if_any": true,
				"names_auditor_and_qualifications": true,
				"names_responsible_individuals": true,
				"signed_independence_statement": true,
			},
			"revenue_tier": "over_100m",
		},
		"data_practices": {
			"data_minimization": {
				"collected_only_for_disclosed_purposes": true,
				"collection_limited_to_necessary": true,
				"not_used_incompatibly": true,
			},
			"data_protection_assessments": {
				"conducted_for_high_risk": true,
				"reviewed_annually": true,
				"submitted_to_cppa_on_request": true,
			},
			"purpose_limitation": {
				"not_sold_beyond_disclosed_categories": true,
				"not_used_beyond_disclosed_purposes": true,
			},
			"retention_limitation": {
				"automated_deletion_enforced": true,
				"not_retained_longer_than_necessary": true,
				"schedule_established_and_documented": true,
			},
			"security": {
				"breach_notification_within_72_hours": true,
				"consumer_notification_without_unreasonable_delay": true,
				"reasonable_security_implemented": true,
			},
		},
		"risk_assessments": {
			"activities": {
				"admt_significant_decision": {
					"assessment_completed_before_processing": true,
					"in_use": true,
				},
				"inference_from_observation_work_or_education": {
					"assessment_completed_before_processing": true,
					"in_use": true,
				},
				"inference_in_sensitive_location": {
					"assessment_completed_before_processing": true,
					"in_use": true,
				},
				"selling_or_sharing": {
					"assessment_completed_before_processing": true,
					"in_use": true,
				},
				"sensitive_personal_information": {
					"assessment_completed_before_processing": true,
					"in_use": true,
				},
				"training_admt_or_biometric_technology": {
					"assessment_completed_before_processing": true,
					"in_use": true,
				},
			},
			"admt_provider": {
				"facts_provided_for_recipient_assessments": true,
				"provides_admt_to_recipient_businesses": true,
			},
			"report": {
				"admt_logic_and_output_documented": true,
				"benefits_specific": true,
				"categories_and_minimum_pi_identified": true,
				"contributors_identified": true,
				"decision_to_initiate_documented": true,
				"negative_impacts_with_sources": true,
				"operational_elements_documented": true,
				"purpose_specific_not_generic": true,
				"reviewed_and_approved_by_decision_authority": true,
				"safeguards_documented": true,
			},
			"stakeholders": {
				"processing_employees_included": true,
			},
			"submission": {
				"includes_required_contents": true,
				"reports_available_within_30_days_of_request": true,
				"submitted_by_april_1": true,
				"submitted_by_responsible_executive": true,
			},
			"timing": {
				"legacy_assessment_scheduled": true,
				"legacy_processing_assessed": true,
				"legacy_processing_continuing": true,
				"retained_five_years_or_duration_of_processing": true,
				"reviewed_at_least_every_three_years": true,
				"updated_within_45_days_of_material_change": true,
			},
		},
		"sensitive_data": {
			"account_credentials": {
				"not_stored_in_plaintext": true,
			},
			"automated_decisions": {
				"logic_explanation_available": true,
				"opt_out_available": true,
			},
			"biometric_data": {
				"consent_obtained": true,
				"retention_limited": true,
			},
			"genetic_data": {
				"access_controls_implemented": true,
				"not_sold": true,
			},
			"government_ids": {
				"access_limited_and_encrypted": true,
			},
			"health_information": {
				"hipaa_aligned_controls": true,
			},
			"mail_email_text": {
				"not_accessed_except_for_delivery": true,
			},
			"precise_geolocation": {
				"explicit_purpose_limitation": true,
			},
			"racial_ethnic_origin": {
				"dpias_conducted": true,
			},
			"religious_beliefs": {
				"collection_minimized": true,
			},
			"sex_life_orientation": {
				"not_collected_unless_necessary": true,
			},
			"union_membership": {
				"collection_minimized": true,
			},
		},
	},
}

# ── Mutations ───────────────────────────────────────────────────────────────
# Every leaf of an all-pass fixture is evidence. A boolean is swapped for the strings "false", "true"
# and "no", for null, 0 and 1; a number for its string form and null; a text value for null and a
# number; and every leaf is removed once. None of the resulting inputs may pass.
_leaves(fx) := [[path, value] |
	walk(fx, [path, value])
	not is_object(value)
]

_swaps(value) := ["false", "true", "no", null, 0, 1] if is_boolean(value)

_swaps(value) := [sprintf("%v", [value]), null] if is_number(value)

_swaps(value) := [null, 7] if is_string(value)

_bad_inputs(fx) := array.concat(
	[{"case": sprintf("%s := %s", [concat(".", path), json.marshal(swap)]), "input": json.patch(fx, [{"op": "replace", "path": path, "value": swap}])} |
		some [path, value] in _leaves(fx)
		some swap in _swaps(value)
	],
	[{"case": sprintf("%s removed", [concat(".", path)]), "input": json.patch(fx, [{"op": "remove", "path": path}])} |
		some [path, _] in _leaves(fx)
	],
)

# Modules that passed on empty input never existed here; keep it that way.
# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_main_bad_inputs_9 if {
	sum([count(_slice(_main_bad_inputs, i, 9)) | some i in numbers.range(0, 8)]) == count(_main_bad_inputs)
	every i in numbers.range(0, 8) {
		every k, x in _slice(_main_bad_inputs, i, 9) {
			x == _main_bad_inputs[i + (k * 9)]
		}
	}
}

test_empty_input_fails_every_module if {
	every name, _ in fixtures {
		not data.ccpa[name].compliant with input as {}
	}
	not data.ccpa.main.compliance_report.compliant with input as {}
}

# No `with input`: the input document is undefined, as when the caller sends no input at all.
test_no_input_document_fails_like_empty_input if {
	every name, _ in fixtures {
		on_empty := data.ccpa[name].violations with input as {}
		on_nothing := data.ccpa[name].violations
		count(on_empty) > 0
		on_nothing == on_empty
	}
	r := data.ccpa.main.compliance_report
	r.compliant == false
	r.failed_controls == 7
}

# A section sent as null reads as an empty section; the report stays defined.
test_null_section_fails_and_report_stays_defined if {
	every name, _ in fixtures {
		inp := json.patch(all_pass_input, [{"op": "replace", "path": ["ccpa", name], "value": null}])
		r := data.ccpa.main.compliance_report with input as inp
		r.compliant == false
		r.modules[name].compliant == false
	}
}

test_all_pass_fixture_passes_every_module if {
	every name, fx in fixtures {
		data.ccpa[name].compliant with input as fx
		count(data.ccpa[name].violations) == 0 with input as fx
	}
}

_passing_mutations := [sprintf("%s: %s", [name, bad.case]) |
	some name, fx in fixtures
	some bad in _bad_inputs(fx)
	not bad.case in _either_or
	data.ccpa[name].compliant with input as bad.input
]

# §7155(b): before 2027-12-31 a legacy activity is covered by a completed assessment or by a scheduled one.
# The fixture states both, so taking one away (removed or null) still leaves the other; a wrongly typed value
# is still a finding and stays in the mutation set.
_either_or := {sprintf("ccpa.risk_assessments.timing.%s%s", [field, suffix]) |
	some field in ["legacy_processing_assessed", "legacy_assessment_scheduled"]
	some suffix in [" removed", " := null"]
}

test_no_mutated_fixture_passes if {
	_passing_mutations == []
}

# The audit's case: every yes/no fact of the business-obligations module sent as the string "false".
test_business_obligations_string_false_is_not_a_pass if {
	inp := {"ccpa": {"business_obligations": {section: {field: "false" | some field, _ in facts} |
		some section, facts in fixtures.business_obligations.ccpa.business_obligations
	}}}
	r := data.ccpa.business_obligations.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 18
	every v in r.violations {
		contains(v, "is not a boolean (got string)")
	}
}

test_finding_names_the_evidence_problem if {
	base := fixtures.consumer_rights
	path := ["ccpa", "consumer_rights", "non_discrimination", "no_penalty_for_rights_exercise"]
	missing := data.ccpa.consumer_rights.violations with input as json.patch(base, [{"op": "remove", "path": path}])
	some m in missing
	endswith(m, "evidence missing: ccpa.consumer_rights.non_discrimination.no_penalty_for_rights_exercise not collected")
	wrong := data.ccpa.consumer_rights.violations with input as json.patch(base, [{"op": "replace", "path": path, "value": "true"}])
	some w in wrong
	endswith(w, "evidence invalid: ccpa.consumer_rights.non_discrimination.no_penalty_for_rights_exercise is not a boolean (got string)")
	collected_false := data.ccpa.consumer_rights.violations with input as json.patch(base, [{"op": "replace", "path": path, "value": false}])
	count(collected_false) == 1
	every f in collected_false {
		not contains(f, "evidence")
	}
}

# A condition is stated, never inferred from a missing field.
test_data_broker_condition_must_be_stated if {
	base := fixtures.business_obligations
	path := ["ccpa", "business_obligations", "data_broker", "applicable"]
	undeclared := data.ccpa.business_obligations.violations with input as json.patch(base, [{"op": "remove", "path": path}])
	some m in undeclared
	startswith(m, "CPRA §1798.99.80: applicability not determined")
	declared_no := json.patch(base, [{"op": "replace", "path": path, "value": false}, {"op": "remove", "path": ["ccpa", "business_obligations", "data_broker", "registered_with_cppa"]}])
	data.ccpa.business_obligations.compliant with input as declared_no
}

# ── Aggregator: the seven modules are the controls ──────────────────────────
_consistent(r) if {
	r.total_controls == 7
	(r.passed_controls + r.failed_controls) + r.not_applicable_controls == r.total_controls
	r.violation_count == count(r.violations)
	r.violation_count == r.failed_controls
	r.violation_count <= r.total_controls
	r.finding_count == count(r.findings)
	r.modules_passing == r.passed_controls
}

test_main_report_is_consistent_on_empty_input if {
	r := data.ccpa.main.compliance_report with input as {}
	_consistent(r)
	r.failed_controls == 7
	r.finding_count > 100
}

test_main_passes_the_all_pass_input if {
	r := data.ccpa.main.compliance_report with input as all_pass_input
	r.compliant == true
	_consistent(r)
	r.failed_controls == 0
	r.finding_count == 0
}

test_main_one_failing_module_is_one_violation if {
	inp := json.patch(all_pass_input, [{"op": "replace", "path": ["ccpa", "sensitive_data", "account_credentials", "not_stored_in_plaintext"], "value": "true"}])
	r := data.ccpa.main.compliance_report with input as inp
	r.compliant == false
	_consistent(r)
	r.failed_controls == 1
	r.finding_count == 1
	contains(r.violations[0], "Sensitive Personal Information")
}

# the mutated inputs of the all-pass input document, built once per test (a rule, so not once per use)
_main_bad_inputs := _bad_inputs(all_pass_input)

test_main_never_passes_a_mutated_input_slice_0 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 0, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}

test_main_never_passes_a_mutated_input_slice_1 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 1, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}

test_main_never_passes_a_mutated_input_slice_2 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 2, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}

test_main_never_passes_a_mutated_input_slice_3 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 3, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}

test_main_never_passes_a_mutated_input_slice_4 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 4, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}

test_main_never_passes_a_mutated_input_slice_5 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 5, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}

test_main_never_passes_a_mutated_input_slice_6 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 6, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}

test_main_never_passes_a_mutated_input_slice_7 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 7, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}

test_main_never_passes_a_mutated_input_slice_8 if {
	passing := [bad.case |
		some bad in _slice(_main_bad_inputs, 8, 9)
		not bad.case in _either_or
		r := data.ccpa.main.compliance_report with input as bad.input
		r.compliant == true
	]
	passing == []
}
