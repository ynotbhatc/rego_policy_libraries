package nist.sp800_53.system_communications_logic_test

# Logic tests for system_communications/sc_controls.rego. Every case states its input inline (no helper does
# `with input as`, which the wasm build rejects). Unit cases with a partial input check one id; the cases built on
# the all-pass fixture change one fact and must flip exactly that id.

import rego.v1

_pass := {"sc_controls": {"policy": {"documented": true}, "app_partitioning": {"separated": true}, "security_function_isolation": {"implemented": true}, "shared_resources": {"residual_information_protected": true}, "denial_of_service": {"protections": true}, "boundary_protection": {"deployed": true, "access_points": {"external_connections": 2, "odp": {"max_external_connections": 4}}, "external_telecom": {"services_without_managed_interface": 0, "interfaces_without_flow_policy": 0, "unprotected_interfaces": 0, "undocumented_exceptions": 0, "control_plane_traffic_controlled": true, "exception_review": {"days_since_last": 30, "odp": {"frequency_days": 365}}}, "deny_by_default": {"interfaces_allowing_by_default": 0}, "split_tunneling": {"unsafe_profiles": 0}, "proxy": {"authenticated_proxy_enforced": true}, "exfiltration": {"prevention_enforced": true, "testing": {"days_since_last": 90, "odp": {"frequency_days": 365}}}, "host_based": {"components_without_protection": 0}, "fail_secure": {"devices_fail_open": 0}, "dynamic_isolation": {"components_without_capability": 0}, "component_isolation": {"components_not_isolated": 0}}, "transmission_confidentiality": {"protected": true, "encrypted": true}, "transmission_integrity": {"protected": true, "cryptographic": true}, "network_disconnect": {"timeout_configured": true}, "cryptographic_key_mgmt": {"documented": true, "availability": {"key_recovery_enabled": true}}, "cryptographic_protection": {"odp": {"required_standards": ["FIPS 140-3"]}, "standards_implemented": ["FIPS 140-3"]}, "collaborative_devices": {"disabled_when_unused": true}, "public_key_infrastructure": {"certificates_managed": true}, "mobile_code": {"controls_enforced": true}, "secure_dns": {"dnssec_enforced": true}, "name_resolution_architecture": {"fault_tolerant": true, "role_separation": true}, "session_authenticity": {"protected": true}, "protection_of_info_at_rest": {"protected": true, "encrypted": true}, "process_isolation": {"separate_execution_domains": true}, "time_synchronization": {"clocks_synchronized": true, "authoritative_source_synchronized": true}, "resource_availability": {"resources_without_allocation": 0}, "trusted_path": {"isolated_path_provided": true, "user_invocable": true}, "attribute_transmission": {"odp": {"attributes": ["classification", "pii"]}, "attributes_associated": ["classification", "pii", "owner"]}, "fail_in_known_state": {"failure_types_without_known_state": 0}, "thin_nodes": {"components_exceeding_minimal": 0}, "decoys": {"deployed": true}, "platform_independent_applications": {"odp": {"applications": ["java-portal"]}, "included": ["java-portal"]}, "heterogeneity": {"components_single_technology": 0}, "concealment_misdirection": {"odp": {"techniques": ["address randomization"]}, "techniques_employed": ["address randomization"]}, "covert_channel_analysis": {"attestation": {"attested": true, "by": "ISSO J. Doe", "date": "2026-11-01"}}, "system_partitioning": {"components_not_separated": 0}, "non_modifiable_executables": {"operating_environment_read_only": true, "applications_not_read_only": 0}, "external_malicious_code_identification": {"seeking_components_deployed": true}, "distributed_processing": {"components_single_location": 0}, "out_of_band_channels": {"attestation": {"attested": true, "by": "ISSO J. Doe", "date": "2026-11-01"}}, "operations_security": {"attestation": {"attested": true, "by": "ISSO J. Doe", "date": "2026-11-01"}}, "wireless_link_protection": {"unprotected_links": 0}, "port_io_access": {"enabled_prohibited_ports": 0}, "sensor_capability": {"remote_activation_prohibited": true, "use_indicated": true}, "usage_restrictions": {"restrictions_established": true, "use_controlled": true}, "detonation_chamber": {"deployed": true}, "cross_domain": {"interfaces_without_enforcement": 0}, "alternate_communications_paths": {"odp": {"paths": ["satcom"]}, "established": ["satcom"]}, "sensor_relocation": {"attestation": {"attested": true, "by": "ISSO J. Doe", "date": "2026-11-01"}}, "hardware_separation": {"boundaries_without_enforcement": 0}, "software_separation": {"boundaries_without_enforcement": 0}, "hardware_write_protect": {"firmware_unprotected": 0, "procedures_documented": true}}}

_finding(v, id) := [x | some x in v; startswith(x, concat("", ["NIST ", id, ":"]))]

# --- report contract ---------------------------------------------------------

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_sc_one_finding_per_evaluated_id_on_empty_input if {
	r := data.nist.sp800_53.system_communications.compliance_report with input as {}
	r.controls_evaluated == 61
	count(r.violations) == count(data.nist.sp800_53.system_communications.evaluated_controls)
	every id in data.nist.sp800_53.system_communications.evaluated_controls {
		count(_finding(r.violations, id)) == 1
	}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.system_communications.evaluated_controls == {"SC-1", "SC-2", "SC-3", "SC-4", "SC-5", "SC-6", "SC-7", "SC-7(3)", "SC-7(4)", "SC-7(5)", "SC-7(7)", "SC-7(8)", "SC-7(10)", "SC-7(12)", "SC-7(18)", "SC-7(20)", "SC-7(21)", "SC-8", "SC-8(1)", "SC-10", "SC-11", "SC-12", "SC-12(1)", "SC-13", "SC-15", "SC-16", "SC-17", "SC-18", "SC-20", "SC-21", "SC-22", "SC-23", "SC-24", "SC-25", "SC-26", "SC-27", "SC-28", "SC-28(1)", "SC-29", "SC-30", "SC-31", "SC-32", "SC-34", "SC-35", "SC-36", "SC-37", "SC-38", "SC-39", "SC-40", "SC-41", "SC-42", "SC-43", "SC-44", "SC-45", "SC-45(1)", "SC-46", "SC-47", "SC-48", "SC-49", "SC-50", "SC-51"}
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
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"access_points": null, "external_telecom": null, "deny_by_default": null, "split_tunneling": null, "proxy": null, "exfiltration": null, "host_based": null, "fail_secure": null, "dynamic_isolation": null, "component_isolation": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 10
	count(_finding(v, "SC-7")) == 0
}

# --- strict booleans (2026-11-19): only true passes the formerly truthy checks ---------------
test_sc1_truthy_yes_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"policy": {"documented": "yes"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc1_string_true_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"policy": {"documented": "true"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc5_number_one_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"denial_of_service": {"protections": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_null_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"deployed": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_false_keeps_original_text if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"deployed": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7")
	count(f) == 1
	contains(f[0], "not deployed at managed interfaces")
}

test_sc17_string_true_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"public_key_infrastructure": {"certificates_managed": "true"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-17")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc18_object_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"mobile_code": {"controls_enforced": {"allow": ["js"]}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-18")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc12_string_false_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"cryptographic_key_mgmt": {"documented": "false"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-12")
	count(f) == 1
	contains(f[0], "evidence missing")
}

# --- High-baseline ids and remaining base controls: one failing and one evidence-missing case each ---
test_sc6_fails if {
	inp := object.union(_pass, {"sc_controls": {"resource_availability": {"resources_without_allocation": 2}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-6")
	count(f) == 1
	contains(f[0], "2 organization-defined resources")
}

test_sc6_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"resource_availability": {"resources_without_allocation": "0"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-6")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_10_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"exfiltration": {"testing": {"days_since_last": 400}}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(10)")
	count(f) == 1
	contains(f[0], "exfiltration tests conducted last 400 days ago")
}

test_sc7_10_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"exfiltration": {"testing": {"odp": null}}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(10)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_12_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"host_based": {"components_without_protection": 1}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(12)")
	count(f) == 1
	contains(f[0], "lack host-based boundary protection")
}

test_sc7_12_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"host_based": {"components_without_protection": null}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(12)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_18_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"fail_secure": {"devices_fail_open": 1}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(18)")
	count(f) == 1
	contains(f[0], "fail open")
}

test_sc7_18_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"fail_secure": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(18)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_20_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"dynamic_isolation": {"components_without_capability": 3}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(20)")
	count(f) == 1
	contains(f[0], "cannot be dynamically isolated")
}

test_sc7_20_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"dynamic_isolation": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(20)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc7_21_fails if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"component_isolation": {"components_not_isolated": 1}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(21)")
	count(f) == 1
	contains(f[0], "not isolated by boundary protection")
}

test_sc7_21_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"boundary_protection": {"component_isolation": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-7(21)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc11_fails if {
	inp := object.union(_pass, {"sc_controls": {"trusted_path": {"user_invocable": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-11")
	count(f) == 1
	contains(f[0], "cannot invoke the trusted path")
}

test_sc11_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"trusted_path": {"isolated_path_provided": "true"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-11")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc12_1_fails if {
	inp := object.union(_pass, {"sc_controls": {"cryptographic_key_mgmt": {"availability": {"key_recovery_enabled": false}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-12(1)")
	count(f) == 1
	contains(f[0], "no key escrow or backup")
}

test_sc12_1_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"cryptographic_key_mgmt": {"availability": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-12(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc16_fails if {
	inp := object.union(_pass, {"sc_controls": {"attribute_transmission": {"attributes_associated": ["classification"]}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-16")
	count(f) == 1
	contains(f[0], "[\"pii\"]")
}

test_sc16_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"attribute_transmission": {"odp": {"attributes": []}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-16")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc24_fails if {
	inp := object.union(_pass, {"sc_controls": {"fail_in_known_state": {"failure_types_without_known_state": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-24")
	count(f) == 1
	contains(f[0], "do not fail to a known state")
}

test_sc24_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"fail_in_known_state": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-24")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc25_fails if {
	inp := object.union(_pass, {"sc_controls": {"thin_nodes": {"components_exceeding_minimal": 4}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-25")
	count(f) == 1
	contains(f[0], "exceed minimal functionality")
}

test_sc25_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"thin_nodes": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-25")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc26_fails if {
	inp := object.union(_pass, {"sc_controls": {"decoys": {"deployed": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-26")
	count(f) == 1
	contains(f[0], "no decoy components")
}

test_sc26_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"decoys": {"deployed": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-26")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc27_fails if {
	inp := object.union(_pass, {"sc_controls": {"platform_independent_applications": {"included": []}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-27")
	count(f) == 1
	contains(f[0], "java-portal")
}

test_sc27_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"platform_independent_applications": {"included": "java-portal"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-27")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc29_fails if {
	inp := object.union(_pass, {"sc_controls": {"heterogeneity": {"components_single_technology": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-29")
	count(f) == 1
	contains(f[0], "diverse set")
}

test_sc29_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"heterogeneity": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-29")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc30_fails if {
	inp := object.union(_pass, {"sc_controls": {"concealment_misdirection": {"techniques_employed": ["honeytokens"]}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-30")
	count(f) == 1
	contains(f[0], "address randomization")
}

test_sc30_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"concealment_misdirection": {"odp": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-30")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc31_fails if {
	inp := object.union(_pass, {"sc_controls": {"covert_channel_analysis": {"attestation": {"attested": false}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-31")
	count(f) == 1
	contains(f[0], "not attested")
}

test_sc31_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"covert_channel_analysis": {"attestation": {"by": ""}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-31")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc32_fails if {
	inp := object.union(_pass, {"sc_controls": {"system_partitioning": {"components_not_separated": 2}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-32")
	count(f) == 1
	contains(f[0], "separate physical or logical domains")
}

test_sc32_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"system_partitioning": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-32")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc34_fails if {
	inp := object.union(_pass, {"sc_controls": {"non_modifiable_executables": {"operating_environment_read_only": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-34")
	count(f) == 1
	contains(f[0], "operating environment is not loaded")
}

test_sc34_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"non_modifiable_executables": {"applications_not_read_only": "0"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-34")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc35_fails if {
	inp := object.union(_pass, {"sc_controls": {"external_malicious_code_identification": {"seeking_components_deployed": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-35")
	count(f) == 1
	contains(f[0], "proactively seek")
}

test_sc35_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"external_malicious_code_identification": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-35")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc36_fails if {
	inp := object.union(_pass, {"sc_controls": {"distributed_processing": {"components_single_location": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-36")
	count(f) == 1
	contains(f[0], "not distributed")
}

test_sc36_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"distributed_processing": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-36")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc37_fails if {
	inp := object.union(_pass, {"sc_controls": {"out_of_band_channels": {"attestation": {"attested": false}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-37")
	count(f) == 1
	contains(f[0], "not attested")
}

test_sc37_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"out_of_band_channels": {"attestation": "yes"}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-37")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc38_fails if {
	inp := object.union(_pass, {"sc_controls": {"operations_security": {"attestation": {"attested": false}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-38")
	count(f) == 1
	contains(f[0], "not attested")
}

test_sc38_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"operations_security": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-38")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc40_fails if {
	inp := object.union(_pass, {"sc_controls": {"wireless_link_protection": {"unprotected_links": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-40")
	count(f) == 1
	contains(f[0], "signal parameter attacks")
}

test_sc40_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"wireless_link_protection": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-40")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc41_fails if {
	inp := object.union(_pass, {"sc_controls": {"port_io_access": {"enabled_prohibited_ports": 5}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-41")
	count(f) == 1
	contains(f[0], "5 organization-defined connection ports")
}

test_sc41_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"port_io_access": {"enabled_prohibited_ports": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-41")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc42_fails if {
	inp := object.union(_pass, {"sc_controls": {"sensor_capability": {"use_indicated": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-42")
	count(f) == 1
	contains(f[0], "explicit indication of sensor use")
}

test_sc42_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"sensor_capability": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-42")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc43_fails if {
	inp := object.union(_pass, {"sc_controls": {"usage_restrictions": {"use_controlled": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-43")
	count(f) == 1
	contains(f[0], "authorized, monitored and controlled")
}

test_sc43_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"usage_restrictions": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-43")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc44_fails if {
	inp := object.union(_pass, {"sc_controls": {"detonation_chamber": {"deployed": false}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-44")
	count(f) == 1
	contains(f[0], "no detonation chamber")
}

test_sc44_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"detonation_chamber": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-44")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc46_fails if {
	inp := object.union(_pass, {"sc_controls": {"cross_domain": {"interfaces_without_enforcement": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-46")
	count(f) == 1
	contains(f[0], "no policy enforcement mechanism")
}

test_sc46_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"cross_domain": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-46")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc47_fails if {
	inp := object.union(_pass, {"sc_controls": {"alternate_communications_paths": {"established": []}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-47")
	count(f) == 1
	contains(f[0], "satcom")
}

test_sc47_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"alternate_communications_paths": {"established": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-47")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc48_fails if {
	inp := object.union(_pass, {"sc_controls": {"sensor_relocation": {"attestation": {"attested": false}}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-48")
	count(f) == 1
	contains(f[0], "not attested")
}

test_sc48_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"sensor_relocation": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-48")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc49_fails if {
	inp := object.union(_pass, {"sc_controls": {"hardware_separation": {"boundaries_without_enforcement": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-49")
	count(f) == 1
	contains(f[0], "hardware-enforced separation")
}

test_sc49_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"hardware_separation": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-49")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc50_fails if {
	inp := object.union(_pass, {"sc_controls": {"software_separation": {"boundaries_without_enforcement": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-50")
	count(f) == 1
	contains(f[0], "software-enforced separation")
}

test_sc50_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"software_separation": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-50")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sc51_fails if {
	inp := object.union(_pass, {"sc_controls": {"hardware_write_protect": {"firmware_unprotected": 1}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-51")
	count(f) == 1
	contains(f[0], "lack hardware-based write-protect")
}

test_sc51_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sc_controls": {"hardware_write_protect": {"procedures_documented": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-51")
	count(f) == 1
	contains(f[0], "evidence missing")
}

# A malformed or empty attestation names the requirement as not attested as well as evidence missing.
test_sc31_absent_attestation_says_not_attested if {
	inp := object.union(_pass, {"sc_controls": {"covert_channel_analysis": null}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(v) == 1
	f := _finding(v, "SC-31")
	count(f) == 1
	contains(f[0], "evidence missing")
	contains(f[0], "not attested")
}

# An enhancement never fails its base control: SC-12(1) missing leaves SC-12 passing.
test_sc12_1_missing_does_not_fail_sc12 if {
	inp := object.union(_pass, {"sc_controls": {"cryptographic_key_mgmt": {"availability": null}}})
	v := data.nist.sp800_53.system_communications.violation with input as inp
	count(_finding(v, "SC-12")) == 0
	count(_finding(v, "SC-12(1)")) == 1
}
