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
		"control_center_communications": {"inventory_maintained": true, "links": [{"encrypted": false, "authenticated": false}]},
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
