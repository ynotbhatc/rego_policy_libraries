package nist.sp800_53.system_communications_logic_test

# Logic tests for system_communications/sc_controls.rego. Every case states its input inline (no helper does
# `with input as`, which the wasm build rejects). Unit cases with a partial input check one id; the cases built on
# the all-pass fixture change one fact and must flip exactly that id.

import rego.v1

_pass := {"sc_controls": {"policy": {"documented": true}, "app_partitioning": {"separated": true}, "security_function_isolation": {"implemented": true}, "shared_resources": {"residual_information_protected": true}, "denial_of_service": {"protections": true}, "boundary_protection": {"deployed": true, "access_points": {"external_connections": 2, "odp": {"max_external_connections": 4}}, "external_telecom": {"services_without_managed_interface": 0, "interfaces_without_flow_policy": 0, "unprotected_interfaces": 0, "undocumented_exceptions": 0, "control_plane_traffic_controlled": true, "exception_review": {"days_since_last": 30, "odp": {"frequency_days": 365}}}, "deny_by_default": {"interfaces_allowing_by_default": 0}, "split_tunneling": {"unsafe_profiles": 0}, "proxy": {"authenticated_proxy_enforced": true}}, "transmission_confidentiality": {"protected": true, "encrypted": true}, "transmission_integrity": {"protected": true, "cryptographic": true}, "network_disconnect": {"timeout_configured": true}, "cryptographic_key_mgmt": {"documented": true}, "cryptographic_protection": {"odp": {"required_standards": ["FIPS 140-3"]}, "standards_implemented": ["FIPS 140-3"]}, "collaborative_devices": {"disabled_when_unused": true}, "public_key_infrastructure": {"certificates_managed": true}, "mobile_code": {"controls_enforced": true}, "secure_dns": {"dnssec_enforced": true}, "name_resolution_architecture": {"fault_tolerant": true, "role_separation": true}, "session_authenticity": {"protected": true}, "protection_of_info_at_rest": {"protected": true, "encrypted": true}, "process_isolation": {"separate_execution_domains": true}, "time_synchronization": {"clocks_synchronized": true, "authoritative_source_synchronized": true}}}

_finding(v, id) := [x | some x in v; startswith(x, concat("", ["NIST ", id, ":"]))]

# --- report contract ---------------------------------------------------------

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_sc_one_finding_per_evaluated_id_on_empty_input if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {}
	r.controls_evaluated == 28
	count(r.violations) == count(data.nist.sp800_53.system_communications.evaluated_controls)
	every id in data.nist.sp800_53.system_communications.evaluated_controls {
		count(_finding(r.violations, id)) == 1
	}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.system_communications.evaluated_controls == {"SC-1", "SC-2", "SC-3", "SC-4", "SC-5", "SC-7", "SC-7(3)", "SC-7(4)", "SC-7(5)", "SC-7(7)", "SC-7(8)", "SC-8", "SC-8(1)", "SC-10", "SC-12", "SC-13", "SC-15", "SC-17", "SC-18", "SC-20", "SC-21", "SC-22", "SC-23", "SC-28", "SC-28(1)", "SC-39", "SC-45", "SC-45(1)"}
}

# --- SC-8 / SC-8(1) -----------------------------------------------------------

test_sc8_both_protected_crypto_passes if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_confidentiality": {"encrypted": true}, "transmission_integrity": {"protected": true, "cryptographic": true}}}
	count(_finding(r.violations, "SC-8")) == 0
	count(_finding(r.violations, "SC-8(1)")) == 0
}

test_sc8_integrity_only_selection_passes_base if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_protection": {"odp": {"properties": ["integrity"]}}, "transmission_integrity": {"protected": true}}}
	count(_finding(r.violations, "SC-8")) == 0
}

test_sc8_selected_property_unprotected_fails if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_protection": {"odp": {"properties": ["confidentiality"]}}, "transmission_integrity": {"protected": true}}}
	f := _finding(r.violations, "SC-8")
	count(f) == 1
	contains(f[0], "confidentiality")
}

test_sc8_no_selection_requires_both if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_confidentiality": {"encrypted": true}}}
	f := _finding(r.violations, "SC-8")
	count(f) == 1
	contains(f[0], "integrity")
}

test_sc8_missing_evidence_fails if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {}}
	f := _finding(r.violations, "SC-8")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc8_false_is_not_evidence_missing if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_confidentiality": {"protected": false, "encrypted": false}, "transmission_integrity": {"protected": false, "cryptographic": false}}}
	f := _finding(r.violations, "SC-8")
	count(f) == 1
	not contains(f[0], "evidence missing")
}

test_sc8_1_is_crypto_not_integrity_label if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_confidentiality": {"encrypted": true}, "transmission_integrity": {"protected": true}}}
	count(_finding(r.violations, "SC-8")) == 0
	f := _finding(r.violations, "SC-8(1)")
	count(f) == 1
	contains(f[0], "Cryptographic protection")
	contains(f[0], "evidence missing")
	not contains(f[0], "Transmission integrity not protected")
}

test_sc8_1_false_is_not_evidence_missing if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_confidentiality": {"encrypted": true}, "transmission_integrity": {"protected": true, "cryptographic": false}}}
	f := _finding(r.violations, "SC-8(1)")
	count(f) == 1
	not contains(f[0], "evidence missing")
}

test_sc8_1_follows_selection if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_protection": {"odp": {"properties": ["confidentiality"]}}, "transmission_confidentiality": {"encrypted": true}}}
	count(_finding(r.violations, "SC-8(1)")) == 0
}

test_sc8_invalid_selection_falls_back_to_both if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"transmission_protection": {"odp": {"properties": ["availability"]}}, "transmission_integrity": {"protected": true}}}
	count(_finding(r.violations, "SC-8")) == 1
}

# --- SC-19 withdrawn ----------------------------------------------------------

test_sc19_withdrawn_never_a_finding if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {}
	every v in r.violations {
		not contains(v, "SC-19")
	}
	not "SC-19" in data.nist.sp800_53.system_communications.evaluated_controls
}

# --- SC-20 / SC-21 ------------------------------------------------------------

test_sc20_sc21_separate_findings_when_missing if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {}}
	count(_finding(r.violations, "SC-20")) == 1
	count(_finding(r.violations, "SC-21")) == 1
}

test_sc20_sc21_pass_with_dnssec if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"secure_dns": {"dnssec_enforced": true}}}
	count(_finding(r.violations, "SC-20")) == 0
	count(_finding(r.violations, "SC-21")) == 0
}

# --- SC-28 / SC-28(1) ---------------------------------------------------------

test_sc28_non_crypto_protection_passes_base if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"protection_of_info_at_rest": {"protected": true, "encrypted": false}}}
	count(_finding(r.violations, "SC-28")) == 0
	f := _finding(r.violations, "SC-28(1)")
	count(f) == 1
	not contains(f[0], "evidence missing")
}

test_sc28_encryption_satisfies_base_and_enhancement if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"protection_of_info_at_rest": {"encrypted": true}}}
	count(_finding(r.violations, "SC-28")) == 0
	count(_finding(r.violations, "SC-28(1)")) == 0
}

test_sc28_unprotected_fails if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"protection_of_info_at_rest": {"protected": false, "encrypted": false}}}
	f := _finding(r.violations, "SC-28")
	count(f) == 1
	not contains(f[0], "evidence missing")
}

test_sc28_missing_evidence_fails if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {}}
	f := _finding(r.violations, "SC-28")
	count(f) == 1
	contains(f[0], "evidence missing")
	not contains(f[0], "via encryption")
}

test_sc28_1_encrypted_string_is_evidence_missing if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"protection_of_info_at_rest": {"protected": true, "encrypted": "true"}}}
	f := _finding(r.violations, "SC-28(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

# --- SC-13: organization-defined cryptography, no hard FIPS requirement ------------------

test_sc13_org_standard_met_passes if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"cryptographic_protection": {"odp": {"required_standards": ["NSA-approved (CNSA 2.0)"]}, "standards_implemented": ["NSA-approved (CNSA 2.0)"]}}}
	count(_finding(r.violations, "SC-13")) == 0
}

test_sc13_fips_not_hard_required if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"cryptographic_protection": {"fips_validated": false, "odp": {"required_standards": ["AES-256-GCM per org policy"]}, "standards_implemented": ["AES-256-GCM per org policy"]}}}
	count(_finding(r.violations, "SC-13")) == 0
}

test_sc13_unmet_standard_fails if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"cryptographic_protection": {"odp": {"required_standards": ["FIPS 140-3"]}, "standards_implemented": ["FIPS 140-2"]}}}
	f := _finding(r.violations, "SC-13")
	count(f) == 1
	contains(f[0], "FIPS 140-3")
}

test_sc13_old_fips_boolean_is_not_evidence if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"cryptographic_protection": {"fips_validated": true}}}
	f := _finding(r.violations, "SC-13")
	count(f) == 1
	contains(f[0], "evidence missing")
}

# --- SC-45 / SC-45(1) ---------------------------------------------------------------

test_sc45_split if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"time_synchronization": {"clocks_synchronized": true, "authoritative_source_synchronized": false}}}
	count(_finding(r.violations, "SC-45")) == 0
	f := _finding(r.violations, "SC-45(1)")
	count(f) == 1
	not contains(f[0], "evidence missing")
}

test_sc45_both_true_passes if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {"time_synchronization": {"clocks_synchronized": true, "authoritative_source_synchronized": true}}}
	count(_finding(r.violations, "SC-45")) == 0
	count(_finding(r.violations, "SC-45(1)")) == 0
}

test_sc45_missing_evidence_fails if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {"sc_controls": {}}
	f := _finding(r.violations, "SC-45")
	count(f) == 1
	contains(f[0], "evidence missing")
	g := _finding(r.violations, "SC-45(1)")
	count(g) == 1
	contains(g[0], "evidence missing")
}

# --- one-fact flips of the all-pass fixture ------------------------------------
test_sc1_false_keeps_original_text if {
	inp := object.union(_pass, {"sc_controls": {"policy": {"documented": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-1")
	count(f) == 1
	contains(f[0], "policy not documented")
}

test_sc1_absent_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"policy": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc10_false_keeps_original_text if {
	inp := object.union(_pass, {"sc_controls": {"network_disconnect": {"timeout_configured": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-10")
	count(f) == 1
	contains(f[0], "timeout not configured")
}

test_sc23_absent_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"session_authenticity": "x"}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-23")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc4_not_protected_fails if {
	inp := object.union(_pass, {"sc_controls": {"shared_resources": {"residual_information_protected": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-4")
	count(f) == 1
	contains(f[0], "shared system resources is not prevented")
}

test_sc4_string_true_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"shared_resources": {"residual_information_protected": "true"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-4")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_3_over_limit_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"access_points": {"external_connections": 5}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(3)")
	count(f) == 1
	contains(f[0], "organization-approved limit is 4")
}

test_sc7_3_string_count_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"access_points": {"external_connections": "1"}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(3)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_3_null_count_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"access_points": {"external_connections": null}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(3)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_3_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"access_points": {"odp": null}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(3)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_4_unmanaged_service_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"external_telecom": {"services_without_managed_interface": 1}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(4)")
	count(f) == 1
	contains(f[0], "1 external telecommunication services have no managed interface")
}

test_sc7_4_exceptions_undocumented_fail if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"external_telecom": {"undocumented_exceptions": 2}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(4)")
	count(f) == 1
	contains(f[0], "mission or business need")
}

test_sc7_4_review_overdue_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"external_telecom": {"exception_review": {"days_since_last": 400}}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(4)")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 365")
}

test_sc7_4_control_plane_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"external_telecom": {"control_plane_traffic_controlled": false}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(4)")
	count(f) == 1
	contains(f[0], "control plane")
}

test_sc7_4_review_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"external_telecom": {"exception_review": {"odp": {"frequency_days": "365"}}}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(4)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_5_allow_by_default_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"deny_by_default": {"interfaces_allowing_by_default": 1}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(5)")
	count(f) == 1
	contains(f[0], "deny network traffic by default")
}

test_sc7_5_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"deny_by_default": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(5)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_7_unsafe_split_tunnel_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"split_tunneling": {"unsafe_profiles": 3}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(7)")
	count(f) == 1
	contains(f[0], "3 remote-access profiles")
}

test_sc7_7_string_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"split_tunneling": {"unsafe_profiles": "0"}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(7)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_8_no_proxy_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"proxy": {"authenticated_proxy_enforced": false}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(8)")
	count(f) == 1
	contains(f[0], "authenticated proxy")
}

test_sc7_8_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"proxy": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(8)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc22_not_fault_tolerant_fails if {
	inp := object.union(_pass, {"sc_controls": {"name_resolution_architecture": {"fault_tolerant": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-22")
	count(f) == 1
	contains(f[0], "not fault-tolerant")
}

test_sc22_no_role_separation_fails if {
	inp := object.union(_pass, {"sc_controls": {"name_resolution_architecture": {"role_separation": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-22")
	count(f) == 1
	contains(f[0], "internal and external roles")
}

test_sc22_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"name_resolution_architecture": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-22")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc39_not_isolated_fails if {
	inp := object.union(_pass, {"sc_controls": {"process_isolation": {"separate_execution_domains": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-39")
	count(f) == 1
	contains(f[0], "separate execution domain")
}

test_sc39_string_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"process_isolation": {"separate_execution_domains": "true"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-39")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_boundary_enhancements_missing_do_not_fail_sc7 if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"access_points": null, "external_telecom": null, "deny_by_default": null, "split_tunneling": null, "proxy": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 5
	count(_finding(v, "SC-7")) == 0
}

# The legacy checks kept their pass condition: a truthy non-boolean still passes them (unchanged behaviour).
test_legacy_pass_condition_unchanged if {
	inp := object.union(_pass, {"sc_controls": {"policy": {"documented": "yes"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 0
}
