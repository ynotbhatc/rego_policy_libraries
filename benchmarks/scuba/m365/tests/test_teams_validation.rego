package scuba_m365.teams_test

import data.scuba_m365.teams
import rego.v1

# Fully-compliant Teams facts. Every violation rule reads a boolean that must
# be true to pass; a per-test override flips exactly one to false so that only
# the rule under test fires.
compliant_input := {"scuba": {"teams": {
	"meetings": {
		"external_control_blocked": true,
		"anonymous_start_blocked": true,
		"lobby_for_anonymous_and_dialin": true,
		"internal_auto_admit": true,
		"dialin_lobby_enforced": true,
		"recording_disabled": true,
		"no_always_record": true,
	},
	"external_access": {
		"per_domain_only": true,
		"unmanaged_inbound_blocked": true,
		"unmanaged_outbound_blocked": true,
	},
	"email_integration_disabled": true,
	"apps": {
		"microsoft_apps_approved_only": true,
		"third_party_approved_only": true,
		"custom_approved_only": true,
	},
}}}

# Helper: assert exactly one violation and that its message names the control.
fires_only(in_obj, control) if {
	v := teams.violations with input as in_obj
	count(v) == 1
	some msg in v
	contains(msg, control)
}

# ── Group 1 — Meeting Policies (MS.TEAMS.1.1-1.7) ─────────────────────────────

test_ms_teams_1_1_external_control if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/meetings/external_control_blocked", "value": false}]), "MS.TEAMS.1.1")
}

test_ms_teams_1_2_anonymous_start if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/meetings/anonymous_start_blocked", "value": false}]), "MS.TEAMS.1.2")
}

test_ms_teams_1_3_lobby_anon_dialin if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/meetings/lobby_for_anonymous_and_dialin", "value": false}]), "MS.TEAMS.1.3")
}

test_ms_teams_1_4_internal_auto_admit if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/meetings/internal_auto_admit", "value": false}]), "MS.TEAMS.1.4")
}

test_ms_teams_1_5_dialin_lobby if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/meetings/dialin_lobby_enforced", "value": false}]), "MS.TEAMS.1.5")
}

test_ms_teams_1_6_recording_disabled if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/meetings/recording_disabled", "value": false}]), "MS.TEAMS.1.6")
}

test_ms_teams_1_7_no_always_record if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/meetings/no_always_record", "value": false}]), "MS.TEAMS.1.7")
}

# ── Group 2 — External User Access (MS.TEAMS.2.1-2.3) ─────────────────────────

test_ms_teams_2_1_per_domain_only if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/external_access/per_domain_only", "value": false}]), "MS.TEAMS.2.1")
}

test_ms_teams_2_2_unmanaged_inbound if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/external_access/unmanaged_inbound_blocked", "value": false}]), "MS.TEAMS.2.2")
}

test_ms_teams_2_3_unmanaged_outbound if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/external_access/unmanaged_outbound_blocked", "value": false}]), "MS.TEAMS.2.3")
}

# ── Group 4 — Email Integration (MS.TEAMS.4.1) ───────────────────────────────

test_ms_teams_4_1_email_integration if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/email_integration_disabled", "value": false}]), "MS.TEAMS.4.1")
}

# ── Group 5 — App Management (MS.TEAMS.5.1-5.3) ───────────────────────────────

test_ms_teams_5_1_microsoft_apps if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/apps/microsoft_apps_approved_only", "value": false}]), "MS.TEAMS.5.1")
}

test_ms_teams_5_2_third_party_apps if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/apps/third_party_approved_only", "value": false}]), "MS.TEAMS.5.2")
}

test_ms_teams_5_3_custom_apps if {
	fires_only(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/teams/apps/custom_approved_only", "value": false}]), "MS.TEAMS.5.3")
}

# ── Compliant input — no violations, compliant true ──────────────────────────

test_fully_compliant_no_violations if {
	r := teams.compliance_report with input as compliant_input
	r.compliant == true
	r.violation_count == 0
	v := teams.violations with input as compliant_input
	count(v) == 0
}

# ── Report is a populated object on EMPTY input (fail-closed) ─────────────────

test_report_populated_on_empty_input if {
	r := teams.compliance_report with input as {}
	r.product == "Microsoft Teams"
	r.baseline == "MS.TEAMS"
	r.controls_evaluated == 14
	r.compliant == false
	r.violation_count == 14
	r.shall_violation_count == 4
	r.should_violation_count == 10
}
