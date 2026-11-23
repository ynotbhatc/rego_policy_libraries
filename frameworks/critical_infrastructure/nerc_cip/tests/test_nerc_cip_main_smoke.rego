package nerc_cip_main_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/nerc_cip/nerc_cip_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nerc_cip_main_loads_on_empty_input if {
	m := data.nerc_cip_main with input as {}
	is_object(m)
}

test_nerc_cip_main_report_wellformed_on_empty_input if {
	report := data.nerc_cip_main.report with input as {}
	is_object(report)
	count(report) > 0
}

test_nerc_cip_main_fail_closed_on_empty_input if {
	report := data.nerc_cip_main.report with input as {}
	not object.get(report, "compliant", false) == true
}

# Semantic review 2026-11-13: records lacking ids must not drop findings; every failing
# standard must surface a finding in all_violations.
test_missing_person_and_eap_ids_still_violate if {
	inp := {
		"personnel": [{"id": "p1", "training_completed": false, "risk_assessment_completed": false}],
		"electronic_access_points": [{"id": "e1", "deny_by_default": false, "authenticated": false}],
		"control_center_communications": {"inventory_maintained": true, "recovery_methods_documented": true, "links": [{"encrypted": false, "authenticated": false, "availability_protected": true}]},
	}
	not data.nerc_cip_main.cip_004_compliant with input as inp
	not data.nerc_cip_main.cip_005_compliant with input as inp
	count(data.nerc_cip_main.personnel_violations) == 2 with input as inp
	count(data.nerc_cip_main.security_perimeter_violations) == 2 with input as inp
	count(data.nerc_cip_main.comms_protection_violations) == 2 with input as inp
}

test_cip_002_014_015_findings_in_all_violations if {
	v := data.nerc_cip_main.all_violations with input as {}
	some a in v
	startswith(a, "CIP-002:")
	some b in v
	startswith(b, "CIP-014:")
	some c in v
	startswith(c, "CIP-015:")
}

test_noncompliant_never_has_empty_violations if {
	not data.nerc_cip_main.nerc_cip_compliant with input as {}
	count(data.nerc_cip_main.all_violations) > 0 with input as {}
	r := data.nerc_cip.main.compliance_report with input as {"bes_cyber_systems": []}
	r.compliant == false
	r.violation_count > 0
	r.failed_controls <= r.total_controls
}

# Audit 2026-11-23: CIP-012-2 (availability, link recovery) and CIP-003-9
# (vendor electronic remote access, low impact) in the product entrypoint.
main_comms := {"inventory_maintained": true, "recovery_methods_documented": true, "links": [{"link_id": "L1", "encrypted": true, "authenticated": true, "availability_protected": true}]}

test_cip_012_2_complete_link_passes if {
	data.nerc_cip_main.cip_012_compliant with input as {"control_center_communications": main_comms}
}

test_cip_012_2_availability_and_recovery_required if {
	no_avail := json.patch(main_comms, [{"op": "remove", "path": "/links/0/availability_protected"}])
	not data.nerc_cip_main.cip_012_compliant with input as {"control_center_communications": no_avail}
	v1 := data.nerc_cip_main.comms_protection_violations with input as {"control_center_communications": no_avail}
	v1 == {"CIP-012: Link L1 has no method against the loss of the ability to communicate (CIP-012-2 R1 Part 1.2)"}

	no_recovery := json.patch(main_comms, [{"op": "replace", "path": "/recovery_methods_documented", "value": "yes"}])
	not data.nerc_cip_main.cip_012_compliant with input as {"control_center_communications": no_recovery}
	v2 := data.nerc_cip_main.comms_protection_violations with input as {"control_center_communications": no_recovery}
	v2 == {"CIP-012: Methods to initiate the recovery of communication links not documented (CIP-012-2 R1 Part 1.3)"}
}

main_org := {"senior_manager": {"designated": true}, "policies": {"documented": true, "approved": true}}

main_low := [{"system_id": "L1", "impact_level": "low"}]

with_vra(vra) := {"bes_cyber_systems": main_low, "cybersecurity_organization": object.union(main_org, {"low_impact_vendor_remote_access": vra})}

test_cip_003_9_vendor_remote_access_low_impact if {
	ok := {"allowed": true, "determine_method": true, "disable_method": true, "malicious_communications_detection": true}
	data.nerc_cip_main.cip_003_compliant with input as with_vra(ok)
	data.nerc_cip_main.cip_003_compliant with input as with_vra({"allowed": false})

	# One missing method is one finding, citing the Attachment 1 section.
	v := data.nerc_cip_main.organization_violations with input as with_vra(object.union(ok, {"disable_method": false}))
	count(v) == 1
	some msg in v
	contains(msg, "Attachment 1 Section 6.2")
}

test_cip_003_9_undeclared_vendor_remote_access_is_evidence_missing if {
	undeclared := {"bes_cyber_systems": main_low, "cybersecurity_organization": main_org}
	not data.nerc_cip_main.cip_003_compliant with input as undeclared
	v := data.nerc_cip_main.organization_violations with input as undeclared
	count(v) == 1
	some msg in v
	startswith(msg, "CIP-003: evidence missing")

	# No inventory is not "no low impact systems".
	not data.nerc_cip_main.cip_003_compliant with input as {"cybersecurity_organization": main_org}

	# An inventory with no low impact system: Section 6 does not apply.
	data.nerc_cip_main.cip_003_compliant with input as {"bes_cyber_systems": [{"system_id": "H1", "impact_level": "high"}], "cybersecurity_organization": main_org}
}

# The declared control universe is the number of violation rules in nerc_cip_main.
test_declared_controls_cover_the_no_facts_findings if {
	r := data.nerc_cip.main.compliance_report with input as {"bes_cyber_systems": []}
	r.total_controls == 48
	r.failed_controls <= r.total_controls
	r.violation_count <= r.total_controls
}
