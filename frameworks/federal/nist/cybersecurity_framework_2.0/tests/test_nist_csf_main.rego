# Tests for nist.csf.main — NIST CSF 2.0 subcategories (CPRT CSF_2_0_0, sha256 de36759d2f3f70a0f28ab9a95505259e568467923295a13d510a068939773e5a).
package nist.csf.main_test

import rego.v1

import data.nist.csf.main

# every fact the 29 facts-basis subcategories read, all true
_green_facts := {
	"identify": {
		"asset_management": {"physical_devices_inventoried": true, "organizational_communication_mapped": true, "resources_prioritized": true},
		"risk_assessment": {
			"asset_vulnerabilities_identified": true, "cyber_threat_intelligence_received": true,
			"threats_identified_and_documented": true, "potential_impacts_identified": true, "risk_determined": true,
		},
	},
	"detect": {
		"anomalies_events": {"detected_events_analyzed": true, "event_data_aggregated": true, "impact_determined": true},
		"continuous_monitoring": {"network_monitored": true, "physical_environment_monitored": true, "external_provider_activity_monitored": true},
	},
	"respond": {
		"analysis": {"vulnerability_disclosures_addressed": true},
		"communications": {"events_reported_within_criteria": true, "information_shared_with_stakeholders": true},
		"mitigation": {"incidents_contained": true},
	},
	"recover": {"recovery_planning": {"recovery_plan_executed": true}},
	"governance": {"risk_calculation": {"standardized_methodology": true, "consistent_metrics": true, "regular_monitoring": true}},
	"access_control": {
		"identity_proofing": {"verification_processes": true, "credential_binding": true, "assertion_mechanisms": true},
		"authentication": {"strong_authentication": true, "device_authentication": true, "multi_factor_required": true},
		"permissions": {"least_privilege_implemented": true, "separation_of_duties": true, "regular_access_reviews": true},
		"physical_access": {"controlled_access_points": true, "visitor_management": true, "monitoring_systems": true},
	},
	"awareness_training": {"all_users_trained": true, "regular_updates": true, "role_specific_training": true},
	"data_security": {
		"at_rest": {"encryption_implemented": true, "access_controls": true, "integrity_monitoring": true},
		"in_transit": {"encryption_required": true, "secure_protocols": true, "integrity_verification": true},
		"availability": {"capacity_planning": true, "redundancy_implemented": true, "performance_monitoring": true},
	},
	"information_protection": {"backups": {"regular_backups": true, "tested_restoration": true, "secure_storage": true}},
}

_all_attested := {sid: true | some sid, _ in main.subcategories}

_green := object.union(_green_facts, {"nist_csf": {"subcategories": _all_attested}})

test_table_counts_match_cprt if {
	count(main.subcategories) == 106
	count(main.categories) == 22
	count(main.functions) == 6
	count(main.withdrawn) == 79
	count(main.withdrawn_categories) == 12
	count([e | some _, s in main.subcategories; some e in s.examples]) == 363
	count({sid | some sid, s in main.subcategories; s.basis == "facts"}) == 29
	count({sid | some sid, s in main.subcategories; s.basis == "attestation"}) == 77
}

test_per_function_counts_match_cprt if {
	counts := {f: n | some f, _ in main.functions; n := count({sid | some sid, s in main.subcategories; s.function == f})}
	counts == {"GV": 31, "ID": 21, "PR": 22, "DE": 11, "RS": 13, "RC": 8}
}

test_parentage_agrees_with_id_spelling if {
	count({sid | some sid, s in main.subcategories; not startswith(sid, concat("", [s.category, "-"]))}) == 0
	count({sid | some sid, s in main.subcategories; main.categories[s.category].function != s.function}) == 0
	count({c | some c, cat in main.categories; not startswith(c, concat("", [cat.function, "."]))}) == 0
	count({e.ref | some sid, s in main.subcategories; some e in s.examples; not startswith(e.ref, concat("", [sid, "."]))}) == 0
	count({sid | some sid, _ in main.subcategories; main.withdrawn[sid]}) == 0
}

test_every_facts_subcategory_fails_on_missing_facts if {
	r := main.compliance_report with input as {"nist_csf": {"subcategories": _all_attested}}
	facts := {sid | some sid, s in main.subcategories; s.basis == "facts"}
	failed := {sid | some sid in facts; r.subcategories[sid].satisfied == false}
	failed == facts
}

test_every_fact_violation_names_a_facts_subcategory if {
	r := main.compliance_report with input as {}
	every v in r.violations {
		not contains(v, "Module Contract")
	}
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.subcategories_satisfied == 0
	r.violation_count == 107 # FAIL-CLOSED + 77 attestation rows + 29 facts rows
}

test_non_object_container_fails_closed if {
	r := main.compliance_report with input as object.union(_green_facts, {"nist_csf": {"subcategories": true}})
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_all_attested_and_green_facts_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.subcategories_satisfied == 106
	r.basis_counts == {"facts": 29, "attestation": 77}
	r.total_controls == 106
	r.standard_total == 106
	every _, fr in r.functions {
		fr.compliant == true
	}
	every _, fs in r.function_summary {
		fs.compliant == true
	}
}

test_attestation_alone_is_not_enough if {
	r := main.compliance_report with input as {"nist_csf": {"subcategories": _all_attested}}
	r.compliant == false
	r.subcategories_satisfied == 77
}

test_one_false_attestation_row_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_csf/subcategories/GV.OC-03", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.subcategories["GV.OC-03"].satisfied == false
	r.subcategories["GV.OC-03"].basis == "attestation"
	r.categories["GV.OC"].not_satisfied == ["GV.OC-03"]
	r.functions.GV.not_satisfied == ["GV.OC-03"]
	r.function_summary.govern.compliant == false
	r.function_summary.identify.compliant == true
	some v in r.violations
	contains(v, "GV.OC-03")
	contains(v, "Legal, regulatory, and contractual requirements regarding cybersecurity")
}

test_non_true_value_is_not_attested if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_csf/subcategories/RC.CO-04", "value": "yes"}])
	r := main.compliance_report with input as inp
	r.subcategories["RC.CO-04"].satisfied == false
}

test_one_false_fact_fails_its_subcategory if {
	inp := json.patch(_green, [{"op": "replace", "path": "/access_control/physical_access/visitor_management", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.subcategories["PR.AA-06"].satisfied == false
	r.subcategories["PR.AA-06"].basis == "facts"
	r.categories["PR.AA"].not_satisfied == ["PR.AA-06"]
	some v in r.violations
	contains(v, "NIST CSF 2.0 PR.AA-06")
}

test_attestation_for_facts_id_is_ignored if {
	inp := json.patch(_green, [{"op": "replace", "path": "/nist_csf/subcategories/PR.AA-06", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == true
}

test_unknown_id_is_a_violation if {
	inp := json.patch(_green, [{"op": "add", "path": "/nist_csf/subcategories/GV.ZZ-01", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	some v in r.violations
	contains(v, "unknown subcategory id GV.ZZ-01")
}

test_withdrawn_id_is_a_violation if {
	inp := json.patch(_green, [{"op": "add", "path": "/nist_csf/subcategories/PR.AC-01", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "PR.AC-01 is withdrawn in CSF 2.0 (Incorporated into PR.AA-01, PR.AA-05)")
}

test_one_id_per_function_resolves if {
	r := main.compliance_report with input as _green
	main.subcategories["GV.OC-01"].text == "The organizational mission is understood and informs cybersecurity risk management"
	main.subcategories["GV.OC-01"].examples[0].ref == "GV.OC-01.001"
	r.subcategories["GV.OC-01"].satisfied == true
	main.subcategories["ID.AM-01"].text == "Inventories of hardware managed by the organization are maintained"
	r.subcategories["ID.AM-01"].basis == "facts"
	main.subcategories["PR.AA-01"].text == "Identities and credentials for authorized users, services, and hardware are managed by the organization"
	r.subcategories["PR.AA-01"].basis == "attestation"
	main.subcategories["DE.CM-09"].text == "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events"
	main.subcategories["RS.MA-01"].text == "The incident response plan is executed in coordination with relevant third parties once an incident is declared"
	main.subcategories["RC.RP-01"].text == "The recovery portion of the incident response plan is executed once initiated from the incident response process"
	r.subcategories["RC.RP-01"].basis == "facts"
	main.categories["GV.OC"].title == "Organizational Context"
	main.functions.RC.title == "RECOVER"
}

test_legacy_checks_are_data_not_controls if {
	r := main.compliance_report with input as _green
	count(r.legacy_fact_checks) == 72
	count({k | some k, row in r.legacy_fact_checks; row.status == "retired"}) == 46
	count({k | some k, row in r.legacy_fact_checks; row.status == "unmapped"}) == 26
	every k, row in r.legacy_fact_checks {
		_legacy_key_ok(k, row.status)
	}
}

_legacy_key_ok(k, "unmapped") if main.subcategories[k]

_legacy_key_ok(k, "retired") if main.withdrawn[k]

test_rejected_moved_carries_are_attested if {
	main.subcategories["DE.AE-08"].basis == "attestation"
	main.subcategories["RS.MA-03"].basis == "attestation"
	main.compliance_report.legacy_fact_checks["DE.AE-05"].status == "retired" with input as {}
	main.compliance_report.legacy_fact_checks["RS.AN-04"].status == "retired" with input as {}
}
