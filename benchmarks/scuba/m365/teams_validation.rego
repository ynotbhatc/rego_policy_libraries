# CISA SCuBA — Secure Configuration Baseline for Microsoft Teams — 14
# policies (MS.TEAMS.*), per cisagov/ScubaGear (TLP:CLEAR). Removed
# groups (MS.TEAMS.3, 6, 7, 8) are absent by design; IDs are never reused.
#
# Input contract — input.scuba.teams.* (source: Teams PowerShell —
# Get-CsTeamsMeetingPolicy, Get-CsTenantFederationConfiguration,
# Get-CsTeamsClientConfiguration, Get-CsTeamsAppPermissionPolicy;
# absence fails closed):
#
#   meetings.{external_control_blocked, anonymous_start_blocked,
#             lobby_for_anonymous_and_dialin, internal_auto_admit,
#             dialin_lobby_enforced, recording_disabled,
#             no_always_record}                  MS.TEAMS.1.1-1.7
#   external_access.{per_domain_only, unmanaged_inbound_blocked,
#             unmanaged_outbound_blocked}        MS.TEAMS.2.1-2.3
#   email_integration_disabled                   MS.TEAMS.4.1
#   apps.{microsoft_apps_approved_only, third_party_approved_only,
#         custom_approved_only}                  MS.TEAMS.5.1-5.3
#
# OPA query path (module): /v1/data/scuba_m365/teams/compliance_report

package scuba_m365.teams

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Group 1 — Meeting Policies ───────────────────────────────────────────────

violations contains msg if {
	not input.scuba.teams.meetings.external_control_blocked
	msg := "SCuBA MS.TEAMS.1.1v1 (SHOULD): External meeting participants can request control of shared desktops or windows"
}

violations contains msg if {
	not input.scuba.teams.meetings.anonymous_start_blocked
	msg := "SCuBA MS.TEAMS.1.2v2 (SHALL): Anonymous users can start meetings"
}

violations contains msg if {
	not input.scuba.teams.meetings.lobby_for_anonymous_and_dialin
	msg := "SCuBA MS.TEAMS.1.3v1 (SHOULD): Anonymous users and dial-in callers are admitted automatically instead of via lobby"
}

violations contains msg if {
	not input.scuba.teams.meetings.internal_auto_admit
	msg := "SCuBA MS.TEAMS.1.4v1 (SHOULD): Internal users are not admitted automatically"
}

violations contains msg if {
	not input.scuba.teams.meetings.dialin_lobby_enforced
	msg := "SCuBA MS.TEAMS.1.5v1 (SHOULD): Dial-in users can bypass the lobby"
}

violations contains msg if {
	not input.scuba.teams.meetings.recording_disabled
	msg := "SCuBA MS.TEAMS.1.6v1 (SHOULD): Meeting recording is not disabled"
}

violations contains msg if {
	not input.scuba.teams.meetings.no_always_record
	msg := "SCuBA MS.TEAMS.1.7v2 (SHOULD): 'Record an event' is set to Always record"
}

# ── Group 2 — External User Access ───────────────────────────────────────────

violations contains msg if {
	not input.scuba.teams.external_access.per_domain_only
	msg := "SCuBA MS.TEAMS.2.1v2 (SHALL): External access is not restricted to a per-domain allowlist"
}

violations contains msg if {
	not input.scuba.teams.external_access.unmanaged_inbound_blocked
	msg := "SCuBA MS.TEAMS.2.2v2 (SHALL): Unmanaged users can initiate contact with internal users"
}

violations contains msg if {
	not input.scuba.teams.external_access.unmanaged_outbound_blocked
	msg := "SCuBA MS.TEAMS.2.3v2 (SHOULD): Internal users can initiate contact with unmanaged users"
}

# ── Group 4 — Email Integration ──────────────────────────────────────────────

violations contains msg if {
	not input.scuba.teams.email_integration_disabled
	msg := "SCuBA MS.TEAMS.4.1v1 (SHALL): Teams email integration is not disabled"
}

# ── Group 5 — App Management ─────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.teams.apps.microsoft_apps_approved_only
	msg := "SCuBA MS.TEAMS.5.1v2 (SHOULD): Installation of Microsoft apps is not limited to those approved by the agency"
}

violations contains msg if {
	not input.scuba.teams.apps.third_party_approved_only
	msg := "SCuBA MS.TEAMS.5.2v2 (SHOULD): Installation of third-party apps is not limited to those approved by the agency"
}

violations contains msg if {
	not input.scuba.teams.apps.custom_approved_only
	msg := "SCuBA MS.TEAMS.5.3v2 (SHOULD): Installation of custom apps is not limited to those approved by the agency"
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

compliance_report := {
	"product": "Microsoft Teams",
	"baseline": "MS.TEAMS",
	"controls_evaluated": 14,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
