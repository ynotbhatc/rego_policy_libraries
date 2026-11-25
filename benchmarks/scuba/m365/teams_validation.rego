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

# METADATA
# title: "CISA SCuBA — Secure Configuration Baseline for Microsoft Teams — 14"
# custom:
#   class: security
#   framework: scuba_m365
#   source: cisa
#   domains: [saas, m365]
#   coverage:
#     checks: 14
#     cited: 14
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package scuba_m365.teams

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Evidence wording ─────────────────────────────────────────────────────────
# Only the boolean true satisfies a yes/no fact. false is the finding as written. A fact that was not collected,
# and a fact of another type ("true", "false", 0, 1, null), fail the policy too and say so under the same policy id,
# so a collection problem is never reported as a configuration finding and never passes.
_finding(text, path) := text if object.get(input, path, null) == false

_finding(text, path) := sprintf("%s evidence missing — input.%s not collected", [_policy(text), concat(".", path)]) if {
	not _collected(path)
}

_finding(text, path) := sprintf("%s evidence invalid — input.%s must be true or false, got %s", [_policy(text), concat(".", path), json.marshal(v)]) if {
	_collected(path)
	v := object.get(input, path, null)
	not is_boolean(v)
}

# present, including present as null
_collected(path) if {
	parent := object.get(input, array.slice(path, 0, count(path) - 1), null)
	is_object(parent)
	path[count(path) - 1] in object.keys(parent)
}

# "SCuBA MS.X.1.1v1 (SHALL):" from the finding text
_policy(text) := concat("", [split(text, "): ")[0], "):"])

# ── Group 1 — Meeting Policies ───────────────────────────────────────────────

violations contains msg if {
	not input.scuba.teams.meetings.external_control_blocked == true
	text := "SCuBA MS.TEAMS.1.1v1 (SHOULD): External meeting participants can request control of shared desktops or windows"
	msg := _finding(text, ["scuba", "teams", "meetings", "external_control_blocked"])
}

violations contains msg if {
	not input.scuba.teams.meetings.anonymous_start_blocked == true
	text := "SCuBA MS.TEAMS.1.2v2 (SHALL): Anonymous users can start meetings"
	msg := _finding(text, ["scuba", "teams", "meetings", "anonymous_start_blocked"])
}

violations contains msg if {
	not input.scuba.teams.meetings.lobby_for_anonymous_and_dialin == true
	text := "SCuBA MS.TEAMS.1.3v1 (SHOULD): Anonymous users and dial-in callers are admitted automatically instead of via lobby"
	msg := _finding(text, ["scuba", "teams", "meetings", "lobby_for_anonymous_and_dialin"])
}

violations contains msg if {
	not input.scuba.teams.meetings.internal_auto_admit == true
	text := "SCuBA MS.TEAMS.1.4v1 (SHOULD): Internal users are not admitted automatically"
	msg := _finding(text, ["scuba", "teams", "meetings", "internal_auto_admit"])
}

violations contains msg if {
	not input.scuba.teams.meetings.dialin_lobby_enforced == true
	text := "SCuBA MS.TEAMS.1.5v1 (SHOULD): Dial-in users can bypass the lobby"
	msg := _finding(text, ["scuba", "teams", "meetings", "dialin_lobby_enforced"])
}

violations contains msg if {
	not input.scuba.teams.meetings.recording_disabled == true
	text := "SCuBA MS.TEAMS.1.6v1 (SHOULD): Meeting recording is not disabled"
	msg := _finding(text, ["scuba", "teams", "meetings", "recording_disabled"])
}

violations contains msg if {
	not input.scuba.teams.meetings.no_always_record == true
	text := "SCuBA MS.TEAMS.1.7v2 (SHOULD): 'Record an event' is set to Always record"
	msg := _finding(text, ["scuba", "teams", "meetings", "no_always_record"])
}

# ── Group 2 — External User Access ───────────────────────────────────────────

violations contains msg if {
	not input.scuba.teams.external_access.per_domain_only == true
	text := "SCuBA MS.TEAMS.2.1v2 (SHALL): External access is not restricted to a per-domain allowlist"
	msg := _finding(text, ["scuba", "teams", "external_access", "per_domain_only"])
}

violations contains msg if {
	not input.scuba.teams.external_access.unmanaged_inbound_blocked == true
	text := "SCuBA MS.TEAMS.2.2v2 (SHALL): Unmanaged users can initiate contact with internal users"
	msg := _finding(text, ["scuba", "teams", "external_access", "unmanaged_inbound_blocked"])
}

violations contains msg if {
	not input.scuba.teams.external_access.unmanaged_outbound_blocked == true
	text := "SCuBA MS.TEAMS.2.3v2 (SHOULD): Internal users can initiate contact with unmanaged users"
	msg := _finding(text, ["scuba", "teams", "external_access", "unmanaged_outbound_blocked"])
}

# ── Group 4 — Email Integration ──────────────────────────────────────────────

violations contains msg if {
	not input.scuba.teams.email_integration_disabled == true
	text := "SCuBA MS.TEAMS.4.1v1 (SHALL): Teams email integration is not disabled"
	msg := _finding(text, ["scuba", "teams", "email_integration_disabled"])
}

# ── Group 5 — App Management ─────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.teams.apps.microsoft_apps_approved_only == true
	text := "SCuBA MS.TEAMS.5.1v2 (SHOULD): Installation of Microsoft apps is not limited to those approved by the agency"
	msg := _finding(text, ["scuba", "teams", "apps", "microsoft_apps_approved_only"])
}

violations contains msg if {
	not input.scuba.teams.apps.third_party_approved_only == true
	text := "SCuBA MS.TEAMS.5.2v2 (SHOULD): Installation of third-party apps is not limited to those approved by the agency"
	msg := _finding(text, ["scuba", "teams", "apps", "third_party_approved_only"])
}

violations contains msg if {
	not input.scuba.teams.apps.custom_approved_only == true
	text := "SCuBA MS.TEAMS.5.3v2 (SHOULD): Installation of custom apps is not limited to those approved by the agency"
	msg := _finding(text, ["scuba", "teams", "apps", "custom_approved_only"])
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
