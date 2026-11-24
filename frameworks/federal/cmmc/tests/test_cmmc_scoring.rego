package cmmc_scoring_test

import rego.v1

# Practice scoring of data.cmmc / data.cmmc.main (32 CFR 170.14): Level 1 is the
# 15 FAR 52.204-21(b)(1) requirements (AC.L1-b.1.i ... SI.L1-b.1.xv), Level 2 the
# 110 NIST SP 800-171 R2 requirements (AC.L2-3.1.1 ...), Level 3 is not modelled.

# Facts for the 17 NIST SP 800-171 R2 requirements that carry the 15 Level 1 safeguards.
level_1_facts := {
	"org_defined": data.cmmc_test_fixtures.org_defined,
	"users": [{"username": "alice", "authorized": true, "system_access": true}],
	"cui_systems": [{"name": "web", "publicly_accessible": true, "cui_posting_controls": true}],
	"access_controls": {"least_privilege_enforced": true, "external_connections_controlled": true},
	"identity": {
		"unique_user_accounts": true, "shared_accounts_documented": true,
		"service_accounts_identified": true, "authentication_required": true,
	},
	"media": {"sanitization_policy_exists": true, "nist_800_88_compliant": true, "sanitization_records_kept": true},
	"physical": {
		"access_control_implemented": true, "authorized_personnel_list_maintained": true,
		"physical_access_logs_kept": true, "visitor_escort_required": true, "visitor_log_maintained": true,
		"visitor_badges_issued": true, "physical_access_audit_logs": true, "access_log_retention_days": 365,
		"access_logs_reviewed_regularly": true, "access_devices_inventoried": true,
		"lost_credentials_revoked": true, "access_devices_audited_annually": true,
	},
	"scp": {
		"external_boundary_monitoring": true, "internal_boundary_controls": true, "network_traffic_controlled": true,
		"dmz_implemented": true, "public_systems_isolated": true, "cui_network_segregated": true,
	},
	"integrity": {
		"flaw_remediation_policy": true, "patch_management_program": true, "critical_patch_days": 14,
		"antimalware_installed": true, "antimalware_realtime_enabled": true,
		"antimalware_covers_entry_exit_points": true, "antimalware_auto_update": true,
		"signature_update_frequency_hours": 4, "periodic_system_scans": true, "scan_frequency_days": 7,
		"realtime_file_scanning": true, "download_scanning_enabled": true,
	},
}

at_level(n) := object.union(level_1_facts, {"cmmc_level": n})

# --- registries ---------------------------------------------------------------

test_registry_sizes_match_32_cfr_170_14 if {
	count(data.cmmc.level_1_requirements) == 15
	count({x.id | some x in data.cmmc.level_1_requirements}) == 15
	count(data.cmmc.level_2_requirements) == 110
	count({r | some r in data.cmmc.level_2_requirements}) == 110
	count({r | some r in data.cmmc.level_3_requirements}) == 24
}

test_level_1_ids_use_far_paragraph_numbers if {
	every x in data.cmmc.level_1_requirements {
		regex.match(`^(AC|IA|MP|PE|SC|SI)\.L1-b\.1\.[ivx]+$`, x.id)
	}
	{n | some x in data.cmmc.level_1_requirements; some n in x.nist} == {
		"3.1.1", "3.1.2", "3.1.20", "3.1.22", "3.5.1", "3.5.2", "3.8.3", "3.10.1", "3.10.3",
		"3.10.4", "3.10.5", "3.13.1", "3.13.5", "3.14.1", "3.14.2", "3.14.4", "3.14.5",
	}
}

# Every one of the 110 requirements is evaluated by exactly one domain module.
test_every_level_2_requirement_has_a_domain_verdict if {
	reports := data.cmmc.domain_reports with input as {"cmmc_level": 2}
	ids := [p.id | some r in reports; some p in r.practices]
	count(ids) == 110
	{i | some i in ids} == {r | some r in data.cmmc.level_2_requirements}
}

# --- the reviewer's case --------------------------------------------------------

reviewer_case := {"cmmc_level": 1, "access_controls": {"least_privilege_enforced": true, "external_connections_controlled": true}}

test_reviewer_case_level_1_without_users_is_not_compliant if {
	not data.cmmc.access_control.compliant with input as reviewer_case
	r := data.cmmc.main.compliance_report with input as reviewer_case
	r.compliant == false
	r.total_controls == 15
	"AC.L1-b.1.i" in r.failed_practices
	"AC.L1-b.1.iv" in r.failed_practices
	some v in r.violations
	startswith(v, "CMMC AC.L1-b.1.i: evidence missing - input.users not collected")
}

# --- Level 1 --------------------------------------------------------------------

test_level_1_full_facts_compliant_without_level_2_facts if {
	r := data.cmmc.main.compliance_report with input as at_level(1)
	r.compliant == true
	r.total_controls == 15
	r.failed_controls == 0
	r.violations == []
	data.cmmc.cmmc_level_1_compliant with input as at_level(1)
}

test_level_1_one_safeguard_split_over_three_requirements_counts_once if {
	inp := json.patch(at_level(1), [
		{"op": "replace", "path": "/physical/visitor_escort_required", "value": false},
		{"op": "remove", "path": "/physical/physical_access_audit_logs"},
	])
	r := data.cmmc.main.compliance_report with input as inp
	r.compliant == false
	r.total_controls == 15
	r.failed_controls == 1
	r.failed_practices == ["PE.L1-b.1.ix"]
}

test_two_findings_for_one_practice_count_once if {
	inp := object.union(at_level(1), {"users": [
		{"username": "a", "authorized": false, "system_access": true},
		{"username": "b", "authorized": false, "system_access": true},
	]})
	r := data.cmmc.main.compliance_report with input as inp
	r.failed_controls == 1
	r.failed_practices == ["AC.L1-b.1.i"]

	# one row for the practice, both findings kept under "findings"
	count([v | some v in r.violations; startswith(v, "CMMC AC.L1-b.1.i: ")]) == 1
	count([v | some v in r.violations; startswith(v, "CMMC AC.L1-b.1.i: 2 findings - (1) Unauthorized user 'a'")]) == 1
	count([v | some v in r.findings; startswith(v, "CMMC AC.L1-b.1.i: Unauthorized user")]) == 2
	r.violation_count == 1
}

test_user_without_authorized_fact_fails_closed if {
	inp := object.union(at_level(1), {"users": [{"username": "a", "system_access": true}]})
	r := data.cmmc.main.compliance_report with input as inp
	r.failed_practices == ["AC.L1-b.1.i"]
	some v in r.violations
	v == "CMMC AC.L1-b.1.i: evidence missing - user 'a' has no boolean 'authorized'"
}

test_media_sanitization_is_a_level_1_practice if {
	inp := json.patch(at_level(1), [{"op": "remove", "path": "/media"}])
	r := data.cmmc.main.compliance_report with input as inp
	r.failed_practices == ["MP.L1-b.1.vii"]
	not data.cmmc.cmmc_level_1_compliant with input as inp
}

# --- Level 2 --------------------------------------------------------------------

test_level_2_scores_110_practices_by_level_2_id if {
	r := data.cmmc.main.compliance_report with input as at_level(2)
	r.total_controls == 110
	r.compliant == false

	# the 17 requirements behind Level 1 pass; the other 93 have no facts
	r.failed_controls == 93
	s := data.cmmc.practice_status with input as at_level(2)
	s["AC.L2-3.1.1"].satisfied == true
	s["PE.L2-3.10.3"].satisfied == true
	s["AC.L2-3.1.8"].satisfied == false
	not data.cmmc.cmmc_level_2_compliant with input as at_level(2)
}

test_level_2_every_finding_names_a_practice if {
	inp := {"cmmc_level": 2}
	c := data.cmmc.input_contract_findings with input as inp
	count(c) == 0
	vs := data.cmmc.all_violations with input as inp
	count(vs) > 0
	reqs := {r | some r in data.cmmc.level_2_requirements}
	every v in vs {
		# same pattern as cmmc.finding_requirement; inlined so the file checks on its own
		x := regex.find_all_string_submatch_n(`^(?:CMMC [A-Z]{2}\.L[12]-(?:b\.1\.[ivx]+ / [A-Z]{2}\.L2-)?)?(3\.[0-9]{1,2}\.[0-9]{1,2}):`, v, 1)
		x[0][1] in reqs
	}
}

test_level_2_failed_never_exceeds_total if {
	r := data.cmmc.main.compliance_report with input as {"cmmc_level": 2}
	r.total_controls == 110
	r.failed_controls == 110

	# one row per failed practice; the findings (several per practice) are listed apart
	r.input_contract_violations == 0
	r.violation_count == r.failed_controls
	r.finding_count > r.failed_controls
}

test_rows_never_outnumber_failed_practices_plus_contract_findings if {
	every inp in [{}, reviewer_case, level_1_facts, at_level(1), at_level(2), at_level(3), {"cmmc_level": "2"}] {
		r := data.cmmc.main.compliance_report with input as inp
		r.violation_count == count(r.violations)
		r.violation_count == r.failed_controls + r.input_contract_violations
		r.passed_controls + r.failed_controls == r.total_controls
	}
}

test_empty_input_rows if {
	r := data.cmmc.main.compliance_report with input as {}
	r.total_controls == 110
	r.failed_controls == 110
	r.input_contract_violations == 2
	r.violation_count == 112
}

# OPA receives no input document at all (empty request body): the report is still defined.
test_no_input_document_report_is_defined if {
	r := data.cmmc.main.compliance_report
	r.compliant == false
	r.failed_controls == 110
	r.assessed_level == null
}

# --- level contract -------------------------------------------------------------

test_missing_level_fails_every_practice if {
	r := data.cmmc.main.compliance_report with input as level_1_facts
	r.compliant == false
	r.total_controls == 110
	r.failed_controls == 110
	some v in r.violations
	startswith(v, "CMMC input contract: FAIL-CLOSED - input.cmmc_level")
}

test_string_level_is_not_a_level if {
	r := data.cmmc.main.compliance_report with input as object.union(level_1_facts, {"cmmc_level": "1"})
	r.compliant == false
	r.failed_controls == r.total_controls
}

test_level_3_is_reported_not_evaluated if {
	r := data.cmmc.main.compliance_report with input as at_level(3)
	r.compliant == false
	r.total_controls == 110
	some v in r.violations
	startswith(v, "CMMC Level 3: not evaluated")
	contains(v, "AC.L3-3.1.2e")
	contains(v, "SI.L3-3.14.6e")
}

test_empty_input_report_contract if {
	r := data.cmmc.main.compliance_report with input as {}
	r.compliant == false
	r.total_controls == 110
	r.failed_controls == 110
	some v in r.violations
	v.control == "FAIL-CLOSED"
}

# --- single source of truth -----------------------------------------------------

test_key_report_and_orchestrator_agree if {
	every inp in [{}, reviewer_case, at_level(1), at_level(2), at_level(3)] {
		r := data.cmmc.main.compliance_report with input as inp
		n := data.cmmc.practices_evaluated with input as inp
		f := data.cmmc.practices_failed with input as inp
		r.total_controls == n
		r.failed_controls == f
		o := data.cmmc.cmmc_compliance_report with input as inp
		o.total_practices == r.total_controls
		o.practices_failing == r.failed_controls
	}
}

# --- scorer on stubbed domains ----------------------------------------------------

test_domain_verdict_true_but_finding_present_fails_practice if {
	stub := {"compliant": true, "violations": ["3.2.1: training not done"], "practices": [
		{"id": "3.2.1", "level": 2, "compliant": true},
		{"id": "3.2.2", "level": 2, "compliant": true},
	]}
	s := data.cmmc.practice_status with data.cmmc.at_report as stub with input as {"cmmc_level": 2}
	s["AT.L2-3.2.1"].satisfied == false
	s["AT.L2-3.2.2"].satisfied == true
}

test_domain_verdict_false_without_finding_gets_evidence_missing if {
	stub := {"compliant": false, "violations": [], "practices": [{"id": "3.2.1", "level": 2, "compliant": false}]}
	f := data.cmmc.practice_findings with data.cmmc.at_report as stub with input as {"cmmc_level": 2}
	"CMMC AT.L2-3.2.1: evidence missing or requirement not met - NIST SP 800-171 R2 3.2.1 is not shown satisfied by the collected facts" in f
}

test_unscored_finding_blocks_compliance if {
	stub := {"compliant": false, "violations": ["training not done"], "practices": []}
	c := data.cmmc.input_contract_findings with data.cmmc.at_report as stub with input as {"cmmc_level": 2}
	"CMMC unscored finding (names no practice): training not done" in c
}
