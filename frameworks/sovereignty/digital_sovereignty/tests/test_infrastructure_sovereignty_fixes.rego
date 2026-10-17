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
