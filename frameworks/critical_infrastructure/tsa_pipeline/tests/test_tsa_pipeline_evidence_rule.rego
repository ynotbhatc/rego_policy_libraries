package tsa_pipeline_evidence_rule_test

import rego.v1

# TSA SD Pipeline-2021-01G and -02G, all twelve sections, with the conditional paths in use (a non-U.S.-citizen alternate, exempt components, shared accounts, pending changes, a denial, unpatchable systems, two reported incidents).
#
# Evidence rule, data-driven over an all-pass fixture: only the boolean true (or,
# for a "does this apply" fact, a stated boolean) is evidence. Every boolean leaf
# is replaced by "false", "true", "no", null, 0 and 1 and removed; every number
# leaf is replaced by its string form and null and removed. None of the mutated
# inputs may be reported compliant.

all_pass := {
	"access_control": {
		"covers_local_and_remote": true,
		"domain_trusts": {
			"management_policy_defined": true,
			"review_schedule_defined": true,
		},
		"identification_authentication": {
			"components_exempt_from_reset": [
				{
					"mitigation_timeframe_defined": true,
					"mitigations_documented": true,
					"name": "rtu-7",
				},
			],
			"password_reset_schedule_defined": true,
			"policy_documented": true,
		},
		"least_privilege": {
			"implemented": true,
			"not_technically_feasible": false,
			"separation_of_duties": true,
		},
		"multi_factor_authentication": {
			"compensating_controls_specified": true,
			"control_room_workstations_exempt": true,
			"implemented": true,
		},
		"policy_documented": true,
		"shared_accounts": {
			"accounts": [
				{
					"credential_rotated_on_departure": true,
					"least_privilege_managed": true,
					"name": "hmi-operator",
					"operations_critical": true,
				},
			],
			"policy_documented": true,
		},
	},
	"assessment_plan": {
		"annual_report": {
			"methods_documented": true,
			"months_since_plan_approval": 6,
			"results_documented": true,
			"submitted": true,
		},
		"architecture_design_review": {
			"conducted": true,
			"months_since_last_review": 10,
			"network_traffic_verified": true,
			"system_log_review_conducted": true,
		},
		"assesses_critical_cyber_systems": true,
		"exists": true,
		"implementation_plan_effectiveness_assessed": true,
		"other_assessment_capabilities": {
			"penetration_testing": true,
			"red_or_purple_team": true,
		},
		"schedule": {
			"annual_coverage_percent": 40,
			"defined": true,
			"three_year_coverage_percent": 100,
		},
		"submission": {
			"months_since_previous_approval": 6,
			"submitted_to_tsa": true,
		},
	},
	"continuous_monitoring": {
		"capabilities": [
			"command_and_control_monitoring",
			"malicious_domain_control",
			"malicious_email_prevention",
			"malicious_ip_blocking",
			"unauthorized_code_blocking",
		],
		"ics_isolation": {
			"capability_exists": true,
			"manual_controls_documented": true,
		},
		"logging": {
			"continuous_collection_and_analysis": true,
			"retention_sufficient_for_investigation": true,
		},
		"policy_documented": true,
		"procedures": [
			"baseline_deviation_auditing",
			"domain_access_auditing",
			"soar_capability",
			"unauthorized_code_response",
		],
	},
	"critical_cyber_systems": {
		"authorized_representatives": [
			{
				"liability_acknowledged": true,
				"name": "rep-1",
			},
		],
		"business_services_evaluated": true,
		"identification_methodology_documented": true,
		"identified": true,
		"managed_security_service_providers": [
			{
				"name": "mssp-1",
				"responsibility_retained": true,
			},
		],
		"none_determination": {
			"declared": false,
		},
		"systems": [
			{
				"included_in_implementation_plan": true,
				"name": "scada-1",
				"type": "operational_technology",
			},
		],
	},
	"cybersecurity_coordinator": {
		"alternates": [
			{
				"clearance_eligible": false,
				"corporate_level": true,
				"email": "a@example.com",
				"known_traveler_number": "123",
				"name": "B",
				"phone": "555",
				"title": "CISO",
				"trusted_traveler_program": "NEXUS",
				"us_citizen": false,
			},
		],
		"available_24x7": true,
		"days_since_information_change": 2,
		"information_current": true,
		"internal_coordination_documented": true,
		"law_enforcement_liaison_established": true,
		"primary": {
			"clearance_eligible": true,
			"corporate_level": true,
			"email": "a@example.com",
			"known_traveler_number": "123",
			"name": "A",
			"phone": "555",
			"title": "CISO",
			"trusted_traveler_program": "NEXUS",
			"us_citizen": true,
		},
		"primary_contact_for_tsa_cisa": true,
		"submitted_to_tsa": true,
		"us_citizen_primary_intelligence_contact": true,
		"us_person_restricted_info_procedures": true,
	},
	"implementation_plan": {
		"amendments": {
			"denials": [
				{
					"days_since_denial": 10,
					"description": "amendment 3",
					"petition_filed": true,
					"reconsideration_intended": true,
				},
			],
			"ineffective_amendment_requested": true,
			"measure_determined_ineffective": true,
			"new_capabilities_obtained": true,
			"new_capability_amendment_requested": true,
			"ownership_amendment_requested": true,
			"ownership_or_control_changed": true,
			"pending_permanent_changes": [
				{
					"amendment_filed": true,
					"days_since_effective": 10,
					"description": "new firewall",
					"duration_days": 60,
				},
			],
		},
		"covers_sections_iii_a_to_iii_e": true,
		"defense_in_depth_described": true,
		"exists": true,
		"logical_controls_described": true,
		"measures_implemented": true,
		"physical_controls_described": true,
		"schedule_met": true,
		"tsa_approved": true,
	},
	"incident_reporting": {
		"covered_incident_categories": [
			"denial_of_service",
			"malicious_software",
			"operational_disruption_potential",
			"physical_attack",
			"unauthorized_access",
		],
		"incidents": [
			{
				"hours_to_report": 10,
				"id": "INC-1",
				"identified_at": "2026-06-01T00:00:00Z",
				"initial_report_incomplete": true,
				"reported_to_cisa": true,
				"sd_reporting_stated": true,
				"supplemental_hours_after_available": 5,
			},
			{
				"hours_to_report": 20,
				"id": "INC-2",
				"identified_at": "2026-07-01T00:00:00Z",
				"initial_report_incomplete": false,
				"reported_to_cisa": true,
				"sd_reporting_stated": true,
			},
		],
		"procedure_documented": true,
		"reports_to_cisa_central": true,
		"required_report_fields": [
			"additional_information",
			"affected_assets",
			"impact_assessment",
			"planned_response",
			"reporter_contact",
			"threat_description",
		],
		"supplemental_within_24h_procedure": true,
	},
	"incident_response_plan": {
		"covers_critical_cyber_systems": true,
		"exercises": {
			"conducted_within_last_12_months": true,
			"months_since_last_exercise": 6,
			"objectives_tested": 2,
			"responsible_personnel_participated": true,
		},
		"exists": true,
		"objectives": {
			"backup_integrity": {
				"backups_secured": true,
				"malicious_code_free_verified": true,
				"stored_separately": true,
			},
			"it_ot_isolation_governance": true,
			"prompt_containment": true,
			"segregation": {
				"infected_devices": true,
				"isolation_and_labeling": true,
				"shared_network_devices": true,
				"volatile_memory_preserved": true,
			},
		},
		"responsibilities": {
			"assigned_by_position": true,
			"resources_identified": true,
		},
		"up_to_date": true,
	},
	"network_segmentation": {
		"external_connections": {
			"connections": [
				{
					"described": true,
					"name": "vendor-vpn",
				},
			],
			"documented": true,
		},
		"it_ot_interdependencies_documented": true,
		"ot_services_traversing_it": {
			"encrypted_in_transit": true,
			"occurs": true,
		},
		"policy_documented": true,
		"zones": {
			"boundaries": [
				{
					"controls_described": true,
					"name": "it-ot",
					"unauthorized_comms_prevented": true,
				},
			],
			"classification_basis": [
				"criticality",
				"consequence",
				"operational_necessity",
			],
			"documented": true,
		},
	},
	"patch_management": {
		"cisa_kev_prioritized": true,
		"critical_patches_current": true,
		"risk_methodology": {
			"categorization_defined": true,
			"criticality_determined": true,
			"implementation_timeline_defined": true,
		},
		"scope": [
			"operating_systems",
			"applications",
			"drivers",
			"firmware",
		],
		"strategy_documented": true,
		"unpatchable_systems": [
			{
				"mitigation_timeline_defined": true,
				"mitigations_described": true,
				"name": "plc-legacy",
				"severe_degradation_justified": true,
			},
		],
	},
	"records": {
		"activity_snapshot": {
			"east_west_traffic": true,
			"log_files": true,
			"north_south_traffic": true,
			"packet_capture_capable": true,
			"packet_capture_max_hours": 24,
		},
		"available_to_tsa_on_request": true,
		"directive_procedures": {
			"disseminated_to_implementers": true,
			"disseminated_to_senior_management": true,
			"receipt_confirmed": true,
		},
		"incorporated_by_reference": true,
		"index_maintained": true,
		"index_ordered_by_requirement": true,
		"previous_materials_relied_upon": true,
		"retrievable_document_types": [
			"activity_snapshot",
			"asset_inventory",
			"firewall_rules",
			"network_diagrams",
			"policy_documents",
		],
		"ssi_protection": {
			"assessment_results": true,
			"plans_and_reports": true,
		},
	},
	"vulnerability_assessment": {
		"alignment_assessed": true,
		"gaps_identified": true,
		"guidelines_section_7_reviewed": true,
		"remediation_measures_identified": true,
		"remediation_timeline_defined": true,
		"ssi_protected_transmission": true,
		"submitted_to_tsa": true,
		"tsa_form_1604_used": true,
	},
}

_bool_leaves := [p | walk(all_pass, [p, v]); is_boolean(v)]

_number_leaves := [p | walk(all_pass, [p, v]); is_number(v)]

_bad_booleans := ["false", "true", "no", null, 0, 1]

_label(p) := concat(".", [sprintf("%v", [s]) | some s in p])

# Each case is a name and a JSON patch; the mutated input is built only when the case is evaluated.
_cases contains {"case": sprintf("%s := %s", [_label(p), json.marshal(bad)]), "patch": [{"op": "replace", "path": p, "value": bad}]} if {
	some p in _bool_leaves
	some bad in _bad_booleans
}

_cases contains {"case": sprintf("%s := %s", [_label(p), json.marshal(bad)]), "patch": [{"op": "replace", "path": p, "value": bad}]} if {
	some p in _number_leaves
	some bad in [sprintf("%v", [object.get(all_pass, p, null)]), null]
}

_cases contains {"case": sprintf("%s removed", [_label(p)]), "patch": [{"op": "remove", "path": p}]} if {
	some p in array.concat(_bool_leaves, _number_leaves)
}

# Every top-level section removed, null, a string and an empty array.
_cases contains {"case": sprintf("%s := %s", [key, json.marshal(bad)]), "patch": [{"op": "replace", "path": [key], "value": bad}]} if {
	some key, _ in all_pass
	some bad in [null, "true", []]
}

_cases contains {"case": sprintf("%s removed", [key]), "patch": [{"op": "remove", "path": [key]}]} if {
	some key, _ in all_pass
}

# The cases are evaluated in 16 shards (first hex digit of the md5 of the case name) so that no single test
# runs long enough to meet the suite's 30 s per-test timeout.
_shards := ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]

# The mutated inputs of one shard that still pass (empty when the evidence rule holds). Only the shard asked
# for is evaluated, and each mutated input is built when its case is reached.
escapes_in(shard) := {c.case |

	# The shard is selected first and as its own list: written as a filter on `_cases` next to the `with`
	# below, OPA 1.10 evaluates the report for every case before it applies the filter (16 times the work).
	some c in [x | some x in _cases; substring(crypto.md5(x.case), 0, 1) == shard]

	inp := json.patch(all_pass, c.patch)
	data.tsa_pipeline.main.compliance_report.compliant == true with input as inp
}

# Every escape, for debugging: opa eval 'data.<this package>.escapes'
escapes := {x | some shard in _shards; some x in escapes_in(shard)}

_clean(shard) if count(escapes_in(shard)) == 0

test_fixture_passes if {
	r := data.tsa_pipeline.main.compliance_report with input as all_pass
	r.compliant == true
	count(r.violations) == 0
}

test_empty_input_fails if {
	r := data.tsa_pipeline.main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

test_the_cases_are_many_and_every_one_is_in_a_shard if {
	count(_cases) > 1000
	every c in _cases {
		substring(crypto.md5(c.case), 0, 1) in _shards
	}
}

test_no_bad_evidence_passes_shard_0 if _clean("0")

test_no_bad_evidence_passes_shard_1 if _clean("1")

test_no_bad_evidence_passes_shard_2 if _clean("2")

test_no_bad_evidence_passes_shard_3 if _clean("3")

test_no_bad_evidence_passes_shard_4 if _clean("4")

test_no_bad_evidence_passes_shard_5 if _clean("5")

test_no_bad_evidence_passes_shard_6 if _clean("6")

test_no_bad_evidence_passes_shard_7 if _clean("7")

test_no_bad_evidence_passes_shard_8 if _clean("8")

test_no_bad_evidence_passes_shard_9 if _clean("9")

test_no_bad_evidence_passes_shard_a if _clean("a")

test_no_bad_evidence_passes_shard_b if _clean("b")

test_no_bad_evidence_passes_shard_c if _clean("c")

test_no_bad_evidence_passes_shard_d if _clean("d")

test_no_bad_evidence_passes_shard_e if _clean("e")

test_no_bad_evidence_passes_shard_f if _clean("f")
