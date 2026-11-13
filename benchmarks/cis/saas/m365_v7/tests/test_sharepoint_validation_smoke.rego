package cis_m365_v7.sharepoint_test

import rego.v1

# Generated smoke test for benchmarks/cis/saas/m365_v7/sharepoint_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_sharepoint_validation_loads_on_empty_input if {
	m := data.cis_m365_v7.sharepoint with input as {}
	is_object(m)
}

test_sharepoint_validation_report_wellformed_on_empty_input if {
	report := data.cis_m365_v7.sharepoint.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_sharepoint_validation_fail_closed_on_empty_input if {
	report := data.cis_m365_v7.sharepoint.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# Semantic review 2026-11-13 regressions.
_has(v, id) := count({m | some m in v; startswith(m, id)}) > 0

test_existing_guests_only_is_not_flagged if {
	v := data.cis_m365_v7.sharepoint.violation with input as {"sharepoint": {"collected": true, "tenant": {"SharingCapability": "ExistingExternalUserSharingOnly", "OneDriveSharingCapability": "ExistingExternalUserSharingOnly"}}}
	not _has(v, "CIS 7.2.6:")
	not _has(v, "CIS 7.2.4:")
}

test_anyone_sharing_still_flagged if {
	v := data.cis_m365_v7.sharepoint.violation with input as {"sharepoint": {"collected": true, "tenant": {"SharingCapability": "ExternalUserAndGuestSharing", "OneDriveSharingCapability": "ExternalUserAndGuestSharing"}}}
	_has(v, "CIS 7.2.6:")
	_has(v, "CIS 7.2.4:")
}

test_collected_but_property_absent_is_not_a_pass if {
	v := data.cis_m365_v7.sharepoint.violation with input as {"sharepoint": {"collected": true, "tenant": {}}}
	_has(v, "CIS 7.2.2:")
	_has(v, "CIS 7.3.1:")
}
