package digital_sovereignty.infrastructure_sovereignty_fixes_test

import rego.v1

inf := data.digital_sovereignty.infrastructure_sovereignty

comp(c) := {"approved_jurisdictions": ["DE"], "infrastructure_components": [c]}

has_control(vs, c) if {
	some v in vs
	v.control == c
}

test_missing_surveillance_flag_violates_is001 if {
	inp := comp({"component_id": "c1", "data_classification": "sensitive"})
	not inf.cloud_act_risk_mitigated with input as inp
	has_control(inf.violations, "IS-001") with input as inp
}

test_surveillance_flag_false_ok if {
	inp := comp({"component_id": "c1", "data_classification": "sensitive", "subject_to_foreign_surveillance_law": false})
	inf.cloud_act_risk_mitigated with input as inp
}

test_surveillance_flag_true_with_mitigation_ok if {
	inp := comp({"component_id": "c1", "data_classification": "sensitive", "subject_to_foreign_surveillance_law": true, "mitigation": {"encryption_before_upload": true}})
	inf.cloud_act_risk_mitigated with input as inp
}

test_surveillance_flag_true_unmitigated_violates if {
	inp := comp({"component_id": "c1", "data_classification": "sensitive", "subject_to_foreign_surveillance_law": true})
	has_control(inf.violations, "IS-001") with input as inp
}

test_public_component_without_flag_not_flagged if {
	inp := comp({"component_id": "c1", "data_classification": "public"})
	inf.cloud_act_risk_mitigated with input as inp
}

test_missing_access_risk_violates_is002 if {
	inp := comp({"component_id": "c2", "data_classification": "sovereign"})
	not inf.sovereign_workloads_not_at_risk with input as inp
	has_control(inf.violations, "IS-002") with input as inp
}

test_access_risk_low_ok if {
	inp := comp({"component_id": "c2", "data_classification": "sovereign", "foreign_government_access_risk": "low"})
	inf.sovereign_workloads_not_at_risk with input as inp
}

test_access_risk_high_violates if {
	inp := comp({"component_id": "c2", "data_classification": "restricted", "foreign_government_access_risk": "high"})
	has_control(inf.violations, "IS-002") with input as inp
}

# Undefined-in-literal trap: report must exist while controls fail.
test_report_defined_when_controls_fail if {
	r := inf.report with input as comp({"component_id": "c1", "data_classification": "sovereign", "subject_to_foreign_surveillance_law": true, "foreign_government_access_risk": "high", "deployment_type": "public_cloud"})
	r.compliant == false
	r.controls["IS-001_cloud_act_risk_mitigated"] == false
	r.controls["IS-002_sovereign_workloads_protected"] == false
	r.controls["IS-007_sovereign_infra"] == false
}

test_report_defined_on_empty_input if {
	r := inf.report with input as {}
	r.compliant == false
	is_object(r.controls)
}

# compliant is false only with an explanation.
test_dns_not_in_jurisdiction_has_violation if {
	has_control(inf.violations, "IS-015") with input as {"approved_jurisdictions": ["DE"], "network_infrastructure": {"dns_provider": {"location_country": "US"}}}
}

test_unclassified_component_has_violation if {
	has_control(inf.violations, "IS-017") with input as comp({"component_id": "c9"})
}

test_firmware_unapproved_has_violation if {
	inp := {"approved_jurisdictions": ["DE"], "hardware_components": [{"component_type": "server", "firmware_origin_country": "CN"}]}
	has_control(inf.violations, "IS-014") with input as inp
}

# decisions 2026-10-19: proprietary-API violation has its own id; migration timeline is enforced.
test_proprietary_api_violation_uses_is018 if {
	inp := {"vendor_lock_in_assessment": {"proprietary_api_dependencies": [{"service_id": "svc1", "mitigation_documented": false}]}}
	has_control(inf.violations, "IS-018") with input as inp
	vs := [v | some v in inf.violations with input as inp; v.service_id == "svc1"]
	count(vs) == 1
	every v in vs {
		v.control == "IS-018"
	}
}

test_long_migration_violates_is019 if {
	inp := {"exit_strategy": {"documented": true, "portability_tested": true, "estimated_migration_days": 120}}
	not inf.migration_timeline_acceptable with input as inp
	has_control(inf.violations, "IS-019") with input as inp
	not inf.compliant with input as inp
}

test_short_migration_ok if {
	inf.migration_timeline_acceptable with input as {"exit_strategy": {"estimated_migration_days": 60}}
}

test_undeclared_migration_estimate_fails_closed if {
	not inf.migration_timeline_acceptable with input as {}
	has_control(inf.violations, "IS-019") with input as {}
	r := inf.report with input as {}
	r.controls["IS-019_migration_timeline"] == false
}
