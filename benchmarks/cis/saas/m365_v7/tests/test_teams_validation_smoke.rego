package cis_m365_v7.teams_test

import rego.v1

# Generated smoke test for benchmarks/cis/saas/m365_v7/teams_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_teams_validation_loads_on_empty_input if {
	m := data.cis_m365_v7.teams with input as {}
	is_object(m)
}

test_teams_validation_report_wellformed_on_empty_input if {
	report := data.cis_m365_v7.teams.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_teams_validation_fail_closed_on_empty_input if {
	report := data.cis_m365_v7.teams.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# Semantic review 2026-11-13 regressions.
_has(v, id) := count({m | some m in v; startswith(m, id)}) > 0

test_8_5_8_follows_external_chat_flag_not_8_5_5_value if {
	ok := data.cis_m365_v7.teams.violation with input as {"teams": {"collected": true, "meeting_policies": [{"Identity": "Global", "MeetingChatEnabledType": "EnabledExceptAnonymous", "AllowExternalNonTrustedMeetingChat": false}]}}
	not _has(ok, "CIS 8.5.8:")
	bad := data.cis_m365_v7.teams.violation with input as {"teams": {"collected": true, "meeting_policies": [{"Identity": "Global", "MeetingChatEnabledType": "Disabled", "AllowExternalNonTrustedMeetingChat": true}]}}
	_has(bad, "CIS 8.5.8:")
}
