package digital_sovereignty.cryptographic_sovereignty_fixes_test

import rego.v1

cs := data.digital_sovereignty.cryptographic_sovereignty

good := {
	"approved_jurisdictions": ["DE"],
	"encrypted_resources": [],
	"encrypted_resources_in_transit": [],
	"hsm_configuration": {
		"deployed": true,
		"type": "fips_140_3",
		"location_country": "DE",
		"vendor_access_possible": false,
		"key_material_leaves_hsm": false,
	},
	"key_management_policies": {
		"rotation_policy_documented": true,
		"rotation_frequency_days": 90,
		"key_ceremony_documented": true,
		"dual_control_enforced": true,
		"split_knowledge_enforced": true,
		"escrow": {"exists": false},
	},
	"encryption_standards": {"algorithms_approved": ["AES-256"], "prohibited_algorithms": ["DES"]},
	"code_signing": {"implemented": true, "private_key_in_approved_jurisdiction": true, "key_location_country": "DE"},
}

with_res(r) := object.union(good, {"encrypted_resources": [r]})

has_control(vs, c) if {
	some v in vs
	v.control == c
}

test_baseline_compliant if cs.compliant with input as good

test_cmk_missing_key_management_violates if {
	inp := with_res({"resource_id": "r1", "data_classification": "sensitive"})
	has_control(cs.violations, "CS-001") with input as inp
	not cs.sensitive_data_uses_customer_managed_keys with input as inp
}

test_cmk_customer_managed_ok if {
	inp := with_res({"resource_id": "r1", "data_classification": "sensitive", "key_management": "customer_managed", "key_location_country": "DE"})
	cs.sensitive_data_uses_customer_managed_keys with input as inp
	cs.keys_in_approved_jurisdiction with input as inp
}

test_unclassified_unencrypted_resource_violates if {
	inp := with_res({"resource_id": "r2", "key_management": "unencrypted"})
	not cs.no_unencrypted_regulated_data with input as inp
	has_control(cs.violations, "CS-003") with input as inp
}

test_public_unencrypted_ok if {
	inp := with_res({"resource_id": "r2", "data_classification": "public", "key_management": "unencrypted"})
	cs.no_unencrypted_regulated_data with input as inp
}

test_customer_key_without_location_violates_cs004 if {
	inp := with_res({"resource_id": "r3", "data_classification": "restricted", "key_management": "customer_managed", "hyok_enabled": true})
	not cs.keys_in_approved_jurisdiction with input as inp
	has_control(cs.violations, "CS-004") with input as inp
}

test_escrow_absent_is_not_compliant if {
	inp := json.remove(good, ["/key_management_policies/escrow"])
	not cs.no_foreign_key_escrow with input as inp
	has_control(cs.violations, "CS-008") with input as inp
}

test_escrow_foreign_holder_violates if {
	inp := object.union(good, {"key_management_policies": object.union(good.key_management_policies, {"escrow": {"exists": true, "foreign_entity_holds_keys": true}})})
	not cs.no_foreign_key_escrow with input as inp
}

test_escrow_domestic_ok if {
	inp := object.union(good, {"key_management_policies": object.union(good.key_management_policies, {"escrow": {"exists": true, "foreign_entity_holds_keys": false}})})
	cs.no_foreign_key_escrow with input as inp
}

test_des_with_missing_prohibited_list_violates if {
	inp := json.remove(with_res({"resource_id": "r4", "data_classification": "public", "key_management": "customer_managed", "algorithm": "DES"}), ["/encryption_standards/prohibited_algorithms"])
	not cs.no_prohibited_algorithms with input as inp
	has_control(cs.violations, "CS-009") with input as inp
}

test_des_with_configured_list_violates if {
	inp := with_res({"resource_id": "r4", "data_classification": "public", "algorithm": "DES"})
	not cs.no_prohibited_algorithms with input as inp
}

test_missing_prohibited_list_reports_evidence_gap if {
	inp := json.remove(good, ["/encryption_standards/prohibited_algorithms"])
	not cs.no_prohibited_algorithms with input as inp
	has_control(cs.violations, "CS-009") with input as inp
}

test_tls_missing_version_violates if {
	inp := object.union(good, {"encrypted_resources_in_transit": [{"connection_id": "c1", "involves_regulated_data": true}]})
	not cs.tls_minimum_version_enforced with input as inp
	has_control(cs.violations, "CS-010") with input as inp
}

# Undefined-in-literal trap: report is produced while a control fails.
test_report_defined_when_cmk_fails if {
	r := cs.report with input as with_res({"resource_id": "r1", "data_classification": "sensitive", "key_management": "provider_managed"})
	r.compliant == false
	r.controls["CS-001_customer_managed_keys"] == false
	r.violation_count > 0
}

test_report_defined_when_tls_and_escrow_fail if {
	inp := object.union(json.remove(good, ["/key_management_policies/escrow"]), {"encrypted_resources_in_transit": [{"connection_id": "c1", "involves_regulated_data": true, "tls_version": "1.0"}]})
	r := cs.report with input as inp
	r.controls["CS-008_no_foreign_key_escrow"] == false
	r.controls["CS-010_tls_minimum_version"] == false
}
