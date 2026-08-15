# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 8 -- Microsoft Teams admin center
#
# 16 of section 8's 17 recommendations are evaluated here. All four
# cmdlets CIS names were verified present in the aac-m365-ee image, so
# unlike section 7 this section follows the benchmark's own audit
# procedure exactly -- no tooling deviation to declare.
#
# NOT EVALUATED: 8.4.1 (app permission policies). CIS marks it Manual and
# names no cmdlet. Get-CsTeamsAppPermissionPolicy plausibly covers it, but
# that is an assumption, and assuming is the defect this library exists to
# avoid. It is reported as unresolved by the attestation module until a
# live-tenant probe settles it.
#
# POLICY COLLECTIONS: meeting and messaging policies are collections, not
# single objects. The Global policy is the tenant default and is what the
# benchmark audits, but a permissive NON-global policy still governs every
# user it is assigned to. Both are checked -- passing on Global alone
# would miss a permissive policy assigned to real users.
#
# Input contract (aac.m365.m365_teams_ps_facts):
#   input.teams.client_configuration       - object
#   input.teams.federation_configuration   - object
#   input.teams.meeting_policies[]         - all policies
#   input.teams.meeting_policies_global    - the Global policy, or null
#   input.teams.messaging_policies[]       - all policies
#   input.teams.unavailable                - {key: reason}

package cis_m365_v7.teams

import rego.v1

default compliant := false

APPROVED_STORAGE_FIELDS := ["AllowDropBox", "AllowBox", "AllowGoogleDrive", "AllowShareFile", "AllowEgnyte"]

default unavailable := {}

unavailable := input.teams.unavailable

default collected := false

collected if {
	input.teams.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

client_config := object.get(input, ["teams", "client_configuration"], {})

federation := object.get(input, ["teams", "federation_configuration"], {})

meeting_policies := object.get(input, ["teams", "meeting_policies"], [])

messaging_policies := object.get(input, ["teams", "messaging_policies"], [])

# ── CIS 8.1.1 -- external file sharing limited to approved services ──
violation contains msg if {
	available("client_configuration")
	some field in APPROVED_STORAGE_FIELDS
	client_config[field] == true
	msg := sprintf("CIS 8.1.1: external file sharing in Teams permits '%s'; only approved cloud storage services should be enabled", [field])
}

# ── CIS 8.1.2 -- email into channel ──────────────────────────────────
violation contains msg if {
	available("client_configuration")
	client_config.AllowEmailIntoChannel == true
	msg := "CIS 8.1.2: users can send emails to a channel email address, which accepts mail from outside the tenant into a Teams channel"
}

# ── CIS 8.2.1 -- external domains restricted ─────────────────────────
violation contains msg if {
	available("federation_configuration")
	federation.AllowFederatedUsers == true
	count(object.get(federation, "AllowedDomains", [])) == 0
	msg := "CIS 8.2.1: external domains are not restricted in the Teams admin center -- federation is open to every domain rather than an allow list"
}

# ── CIS 8.2.2 -- communication with unmanaged Teams users ────────────
violation contains msg if {
	available("federation_configuration")
	federation.AllowTeamsConsumer == true
	msg := "CIS 8.2.2: communication with unmanaged Teams users is not disabled, so staff can be contacted by personal Teams accounts"
}

# ── CIS 8.2.3 -- external users initiating conversations ─────────────
violation contains msg if {
	available("federation_configuration")
	federation.AllowTeamsConsumerInbound == true
	msg := "CIS 8.2.3: external Teams users can initiate conversations; inbound contact from unmanaged accounts should be blocked"
}

# ── CIS 8.2.4 -- trial tenants ───────────────────────────────────────
violation contains msg if {
	available("federation_configuration")
	federation.ExternalAccessWithTrialTenants == "Allowed"
	msg := "CIS 8.2.4: the organization can communicate with accounts in trial Teams tenants, which are trivially created and commonly used for impersonation"
}

# ── Meeting policies (8.5.1 through 8.5.9) ───────────────────────────
# Every policy is checked, not just Global: a permissive non-global policy
# governs every user it is assigned to.

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	p.AllowAnonymousUsersToJoinMeeting == true
	msg := sprintf("CIS 8.5.1: meeting policy '%s' lets anonymous users join a meeting", [p.Identity])
}

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	p.AllowAnonymousUsersToStartMeeting == true
	msg := sprintf("CIS 8.5.2: meeting policy '%s' lets anonymous users and dial-in callers start a meeting, so a meeting can run with no organizer present", [p.Identity])
}

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	not p.AutoAdmittedUsers in {"EveryoneInCompany", "EveryoneInCompanyExcludingGuests", "InvitedUsers", "OrganizerOnly"}
	msg := sprintf("CIS 8.5.3: meeting policy '%s' admits '%s' automatically; only people in the org should bypass the lobby", [p.Identity, p.AutoAdmittedUsers])
}

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	p.AllowPSTNUsersToBypassLobby == true
	msg := sprintf("CIS 8.5.4: meeting policy '%s' lets users dialing in bypass the lobby", [p.Identity])
}

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	p.MeetingChatEnabledType == "Enabled"
	msg := sprintf("CIS 8.5.5: meeting policy '%s' allows meeting chat for anonymous users", [p.Identity])
}

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	p.DesignatedPresenterRoleMode != "OrganizerOnlyUserOverride"
	msg := sprintf("CIS 8.5.6: meeting policy '%s' does not restrict presenting to organizers and co-organizers", [p.Identity])
}

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	p.AllowExternalParticipantGiveRequestControl == true
	msg := sprintf("CIS 8.5.7: meeting policy '%s' lets external participants give or request control of a shared screen", [p.Identity])
}

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	p.MeetingChatEnabledType == "EnabledExceptAnonymous"
	msg := sprintf("CIS 8.5.8: meeting policy '%s' leaves external meeting chat on", [p.Identity])
}

violation contains msg if {
	available("meeting_policies")
	some p in meeting_policies
	p.AllowCloudRecording == true
	msg := sprintf("CIS 8.5.9: meeting policy '%s' has meeting recording on by default", [p.Identity])
}

# ── CIS 8.6.1 -- users can report security concerns ──────────────────
violation contains msg if {
	available("messaging_policies")
	some p in messaging_policies
	p.AllowSecurityEndUserReporting == false
	msg := sprintf("CIS 8.6.1: messaging policy '%s' does not let users report security concerns in Teams, removing the reporting path for suspicious messages", [p.Identity])
}

# ── Fail closed ───────────────────────────────────────────────────────
FACT_CONTROLS := {
	"client_configuration": "8.1.1",
	"federation_configuration": "8.2.1",
	"meeting_policies": "8.5.1",
	"messaging_policies": "8.6.1",
}

violation contains msg if {
	some key, reason in unavailable
	control := object.get(FACT_CONTROLS, key, "8.1.1")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not collected
	msg := "CIS 8.1.1: Teams facts were not collected, so whether external file sharing is limited to approved cloud storage services could not be established -- section 8 was not evaluated (this is not a pass)"
}

compliant if {
	collected
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "8",
	"name": "Microsoft Teams admin center",
	"section_total_controls": 17,
	"controls_evaluated": 16,
	"controls": [
		"8.1.1", "8.1.2",
		"8.2.1", "8.2.2", "8.2.3", "8.2.4",
		"8.5.1", "8.5.2", "8.5.3", "8.5.4", "8.5.5",
		"8.5.6", "8.5.7", "8.5.8", "8.5.9",
		"8.6.1",
	],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	"evidence_strength": {
		"section": "collected with the cmdlets CIS documents (Get-CsTeamsClientConfiguration, Get-CsTenantFederationConfiguration, Get-CsTeamsMeetingPolicy, Get-CsTeamsMessagingPolicy), all verified present in the execution environment. Meeting and messaging policies are evaluated across ALL policies, not only Global, because a permissive non-global policy still governs the users it is assigned to.",
	},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
