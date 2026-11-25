package digital_sovereignty.missing_field_rows_fixes_test

# A row that lacks the field a check reads must produce a finding, not drop out of the check
# (`not x.f in list` and `x.pct > limit` are undefined on a missing field).

import rego.v1

infra := data.digital_sovereignty.infrastructure_sovereignty

ops := data.digital_sovereignty.operational_sovereignty

has_control(vs, c) if {
	some v in vs
	v.control == c
}

base := {
	"approved_jurisdictions": ["DE"],
	"concentration_limits": {"max_single_provider_pct": 70, "max_foreign_provider_pct": 50},
}

test_provider_without_hq_country_is_foreign_and_counted if {
	inp := object.union(base, {"cloud_providers": [{"provider_name": "p1", "data_processed_pct": 90}]})
	not infra.provider_concentration_within_limits with input as inp
	has_control(infra.violations, "IS-003") with input as inp
}

test_provider_without_share_violates_is003 if {
	inp := object.union(base, {"cloud_providers": [{"provider_name": "p1", "hq_country": "US"}]})
	not infra.provider_concentration_within_limits with input as inp
	not infra.foreign_provider_concentration_within_limits with input as inp
	has_control(infra.violations, "IS-003") with input as inp
}

test_provider_share_as_string_violates_is003 if {
	inp := object.union(base, {"cloud_providers": [{"provider_name": "p1", "hq_country": "US", "data_processed_pct": "10"}]})
	has_control(infra.violations, "IS-003") with input as inp
	has_control(infra.violations, "IS-004") with input as inp
}

test_missing_limit_violates_is003 if {
	inp := {"approved_jurisdictions": ["DE"], "cloud_providers": [{"provider_name": "p1", "hq_country": "US", "data_processed_pct": 10}]}
	has_control(infra.violations, "IS-003") with input as inp
}

test_domestic_provider_within_limits_passes if {
	inp := object.union(base, {"cloud_providers": [{"provider_name": "p1", "hq_country": "DE", "data_processed_pct": 90}]})
	infra.provider_concentration_within_limits with input as inp
	infra.foreign_provider_concentration_within_limits with input as inp
}

test_foreign_provider_within_limits_passes if {
	inp := object.union(base, {"cloud_providers": [{"provider_name": "p1", "hq_country": "US", "data_processed_pct": 20}]})
	infra.provider_concentration_within_limits with input as inp
	infra.foreign_provider_concentration_within_limits with input as inp
}

test_hardware_without_manufacturer_country_violates_is005 if {
	inp := object.union(base, {"hardware_components": [{"component_id": "h1", "component_type": "server"}]})
	not infra.hardware_supply_chain_acceptable with input as inp
	has_control(infra.violations, "IS-005") with input as inp
}

test_hardware_without_firmware_origin_fails if {
	inp := object.union(base, {"hardware_components": [{"component_id": "h1", "component_type": "server"}]})
	not infra.firmware_origin_acceptable with input as inp
}

test_sovereign_data_without_deployment_type_violates_is007 if {
	inp := object.union(base, {"infrastructure_components": [{"component_id": "c1", "data_classification": "sovereign"}]})
	not infra.sovereign_data_on_sovereign_infra with input as inp
	has_control(infra.violations, "IS-007") with input as inp
}

test_privileged_person_without_location_violates_os002 if {
	inp := object.union(base, {"personnel": [{"person_id": "u1", "access_level": "admin"}]})
	not ops.privileged_personnel_in_jurisdiction with input as inp
	has_control(ops.violations, "OS-002") with input as inp
}

test_vendor_without_hq_country_violates_os013 if {
	inp := object.union(base, {"vendor_access": [{"vendor_id": "v1", "data_classification_accessed": "sovereign"}]})
	not ops.foreign_vendor_sovereign_access_controlled with input as inp
	has_control(ops.violations, "OS-013") with input as inp
}

test_support_contract_without_location_violates_os014 if {
	inp := object.union(base, {"support_contracts": [{"vendor_id": "s1"}]})
	not ops.support_personnel_in_jurisdiction with input as inp
	has_control(ops.violations, "OS-014") with input as inp
}

test_privileged_person_in_jurisdiction_passes if {
	inp := object.union(base, {"personnel": [{"person_id": "u1", "access_level": "admin", "location_country": "DE"}]})
	ops.privileged_personnel_in_jurisdiction with input as inp
}

test_training_country_missing_is_centralised_training if {
	inp := {"approved_jurisdictions": ["DE"], "ml_training": {"training_data_classification": "sovereign"}}
	not data.digital_sovereignty.ai_sovereignty.sovereign_data_not_centralised_for_training with input as inp
}

test_training_country_approved_passes if {
	inp := {"approved_jurisdictions": ["DE"], "ml_training": {"training_data_classification": "sovereign", "training_infrastructure_country": "DE"}}
	data.digital_sovereignty.ai_sovereignty.sovereign_data_not_centralised_for_training with input as inp
}

test_update_mechanism_without_type_is_checked if {
	inp := {"update_mechanisms": [{"name": "u1"}]}
	not data.digital_sovereignty.software_sovereignty.update_sources_in_jurisdiction with input as inp
}

test_resource_without_algorithm_is_not_approved if {
	inp := {"encryption_standards": {"algorithms_approved": ["AES-256"]}, "encrypted_resources": [{"id": "r1"}]}
	not data.digital_sovereignty.cryptographic_sovereignty.only_approved_algorithms_in_use with input as inp
}

test_algorithm_list_missing_fails if {
	inp := {"encrypted_resources": [{"id": "r1", "algorithm": "AES-256"}]}
	not data.digital_sovereignty.cryptographic_sovereignty.only_approved_algorithms_in_use with input as inp
}

test_approved_algorithm_passes if {
	inp := {"encryption_standards": {"algorithms_approved": ["AES-256"]}, "encrypted_resources": [{"id": "r1", "algorithm": "AES-256"}]}
	data.digital_sovereignty.cryptographic_sovereignty.only_approved_algorithms_in_use with input as inp
}
