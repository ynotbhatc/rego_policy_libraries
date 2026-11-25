package pci_dss_tests.secure_development.requirement_6_test
import rego.v1

# Roll-up behaviour (validation 2026-10-17). Controls are mocked with `with ... as` so these tests
# pin the aggregation logic independent of the evidence schema. The control under test is left
# unmocked and evaluated against an empty input, i.e. it is genuinely failing.

test_all_controls_pass_is_compliant_and_full_score if {
	data.pci_dss.secure_development.requirement_6.pci_requirement_6_compliant with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.memory_corruption_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
	data.pci_dss.secure_development.requirement_6.pci_requirement_6_score == 100 with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.memory_corruption_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
}

test_one_failing_control_gives_partial_score_and_populated_findings if {
	score := data.pci_dss.secure_development.requirement_6.pci_requirement_6_score with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
	score > 0
	score < 100
	f := data.pci_dss.secure_development.requirement_6.pci_requirement_6_findings with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
	count(f) > 0
	not data.pci_dss.secure_development.requirement_6.pci_requirement_6_compliant with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
}

test_failing_memory_corruption_prevented_blocks_compliance if {
	not data.pci_dss.secure_development.requirement_6.pci_requirement_6_compliant with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
}

test_failing_insecure_cryptography_prevented_blocks_compliance if {
	not data.pci_dss.secure_development.requirement_6.pci_requirement_6_compliant with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.memory_corruption_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
}

test_failing_automated_attack_detection_6_4_2_blocks_compliance if {
	not data.pci_dss.secure_development.requirement_6.pci_requirement_6_compliant with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.memory_corruption_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
}

test_failing_sast_dast_does_not_block_compliance_not_a_requirement if {
	data.pci_dss.secure_development.requirement_6.pci_requirement_6_compliant with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.memory_corruption_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true
}

test_failing_sca_does_not_block_compliance_not_a_requirement if {
	data.pci_dss.secure_development.requirement_6.pci_requirement_6_compliant with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.memory_corruption_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true
}

test_waf_implemented_missing_scope_flag_does_not_pass if {
	not data.pci_dss.secure_development.requirement_6.waf_implemented with input as {}
}

test_waf_implemented_explicit_not_in_scope_passes if {
	data.pci_dss.secure_development.requirement_6.waf_implemented with input as {"pci": {"public_web_apps": {"in_scope": false}}}
}

test_automated_attack_detection_missing_scope_flag_does_not_pass if {
	not data.pci_dss.secure_development.requirement_6.automated_attack_detection with input as {}
}

test_automated_attack_detection_explicit_not_in_scope_passes if {
	data.pci_dss.secure_development.requirement_6.automated_attack_detection with input as {"pci": {"public_web_apps": {"in_scope": false}}}
}

test_web_app_pen_testing_missing_scope_flag_does_not_pass if {
	not data.pci_dss.secure_development.requirement_6.web_app_pen_testing with input as {}
}

test_web_app_pen_testing_explicit_not_in_scope_passes if {
	data.pci_dss.secure_development.requirement_6.web_app_pen_testing with input as {"pci": {"public_web_apps": {"in_scope": false}}}
}

# 6.4.1 is superseded by 6.4.2 (PCI SSC FAQ 1593): a failing web_app_pen_testing must not fail requirement 6.
test_superseded_web_app_pen_testing_does_not_block_compliance if {
	data.pci_dss.secure_development.requirement_6.pci_requirement_6_compliant with data.pci_dss.secure_development.requirement_6.secure_development_policies_established as true with data.pci_dss.secure_development.requirement_6.secure_development_roles_defined as true with data.pci_dss.secure_development.requirement_6.secure_sdlc_implemented as true with data.pci_dss.secure_development.requirement_6.developer_security_training as true with data.pci_dss.secure_development.requirement_6.preproduction_security_testing as true with data.pci_dss.secure_development.requirement_6.bespoke_code_review as true with data.pci_dss.secure_development.requirement_6.injection_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.xss_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.authentication_attacks_prevented as true with data.pci_dss.secure_development.requirement_6.memory_corruption_prevented as true with data.pci_dss.secure_development.requirement_6.insecure_cryptography_prevented as true with data.pci_dss.secure_development.requirement_6.security_patch_management as true with data.pci_dss.secure_development.requirement_6.vulnerability_identification as true with data.pci_dss.secure_development.requirement_6.software_inventory_maintained as true with data.pci_dss.secure_development.requirement_6.waf_implemented as true with data.pci_dss.secure_development.requirement_6.automated_attack_detection as true with data.pci_dss.secure_development.requirement_6.sast_dast_implemented as true with data.pci_dss.secure_development.requirement_6.software_composition_analysis as true with data.pci_dss.secure_development.requirement_6.web_app_pen_testing as false
}

_patch(extra) := {"pci": {"patch_management": object.union(
	{
		"process": {"documented": true}, "critical_patches": {"applied_within_30_days": true},
		"testing": {"required_before_deployment": true}, "rollback": {"procedures_defined": true},
	},
	extra,
)}}

# 6.3.3 (v4.0.1): one month for critical patches only; others within the entity-defined time frame.
test_6_3_3_entity_defined_timeframe_for_non_critical_passes if {
	data.pci_dss.secure_development.requirement_6.security_patch_management with input as _patch({"other_patches": {"entity_defined_timeframe": {"met": true}}})
}

test_6_3_3_former_high_within_30_days_still_passes if {
	data.pci_dss.secure_development.requirement_6.security_patch_management with input as _patch({"high_patches": {"applied_within_30_days": true}})
}

test_6_3_3_non_critical_evidence_missing_fails if {
	not data.pci_dss.secure_development.requirement_6.security_patch_management with input as _patch({})
}

test_6_3_3_critical_late_fails if {
	not data.pci_dss.secure_development.requirement_6.security_patch_management with input as _patch({"critical_patches": {"applied_within_30_days": false}, "other_patches": {"entity_defined_timeframe": {"met": true}}})
}

# --- behaviour on the evidence schema (audit 2026-11-17 follow-up) -----------------------------------

_r6 := data.pci_dss.secure_development.requirement_6

test_6_2_2_annual_training_without_owasp_flag_passes if {
	_r6.developer_security_training with input as {"pci": {"developer_training": {"secure_coding": {"conducted": true}, "frequency_months": 12, "records": {"maintained": true}}}}
}

test_6_2_2_thirteen_months_fails if {
	not _r6.developer_security_training with input as {"pci": {"developer_training": {"secure_coding": {"conducted": true}, "frequency_months": 13, "records": {"maintained": true}}}}
}

test_6_2_2_string_frequency_fails if {
	not _r6.developer_security_training with input as {"pci": {"developer_training": {"secure_coding": {"conducted": true}, "frequency_months": "6", "records": {"maintained": true}}}}
}

test_6_2_4_defined_techniques_pass_without_prescribed_ones if {
	_r6.xss_attacks_prevented with input as {"pci": {"secure_coding": {"xss": {"techniques_defined_and_in_use": true}}}}
	_r6.authentication_attacks_prevented with input as {"pci": {"secure_coding": {"authentication": {"techniques_defined_and_in_use": true}}}}
}

test_6_2_4_no_evidence_fails if not _r6.injection_attacks_prevented with input as {}

test_6_3_1_sources_and_ranking_pass_without_30_day_scans if {
	_r6.vulnerability_identification with input as {"pci": {"vulnerability_management": {"industry_sources": {"monitored": true}, "risk_ranking": {"assigned": true}}}}
}

test_6_3_1_no_risk_ranking_fails if {
	not _r6.vulnerability_identification with input as {"pci": {"vulnerability_management": {"industry_sources": {"monitored": true}}}}
}

test_6_3_2_bespoke_and_third_party_inventory_passes if {
	_r6.software_inventory_maintained with input as {"pci": {"software_inventory": {"bespoke": {"documented": true}, "third_party": {"documented": true}}}}
}

test_6_3_2_third_party_missing_fails if {
	not _r6.software_inventory_maintained with input as {"pci": {"software_inventory": {"bespoke": {"documented": true}}}}
}

# 6.4.2 needs the WAF itself (waf.implemented); waf_or_vapt no longer satisfies it (2026-11-21).
_waap(extra) := {"pci": {"public_web_apps": {"in_scope": true}, "waf": {"implemented": true}, "automated_detection": object.union({"logging": {"configured": true}}, extra)}}

test_6_4_2_alert_with_immediate_investigation_passes if {
	_r6.automated_attack_detection with input as _waap({"alerts": {"immediately_investigated": true}})
}

test_6_4_2_blocking_passes if _r6.automated_attack_detection with input as _waap({"active_blocking": {"enabled": true}})

test_6_4_2_neither_block_nor_alert_fails if not _r6.automated_attack_detection with input as _waap({})

test_6_4_2_scope_flag_missing_fails if not _r6.automated_attack_detection with input as {}

test_6_4_2_waf_blocking_mode_passes if {
	_r6.automated_attack_detection with input as {"pci": {"public_web_apps": {"in_scope": true}, "waf": {"implemented": true, "mode": {"blocking": true}}, "automated_detection": {"logging": {"configured": true}}}}
}

test_6_4_2_waf_or_vapt_without_waf_fails if {
	not _r6.automated_attack_detection with input as {"pci": {"public_web_apps": {"in_scope": true}, "automated_detection": {"waf_or_vapt": {"implemented": true}, "logging": {"configured": true}, "active_blocking": {"enabled": true}}}}
}

test_6_4_2_waf_not_implemented_fails if {
	not _r6.automated_attack_detection with input as {"pci": {"public_web_apps": {"in_scope": true}, "waf": {"implemented": false, "mode": {"blocking": true}}, "automated_detection": {"logging": {"configured": true}}}}
}

test_6_4_2_string_scope_flag_fails if {
	not _r6.automated_attack_detection with input as {"pci": {"public_web_apps": {"in_scope": "true"}}}
}

test_6_4_2_out_of_scope_passes_without_waf if {
	_r6.automated_attack_detection with input as {"pci": {"public_web_apps": {"in_scope": false}}}
}
