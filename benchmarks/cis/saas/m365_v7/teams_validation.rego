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

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 17
#     cited: 16
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cis_m365_v7.teams

import rego.v1

default compliant := false

APPROVED_STORAGE_FIELDS := ["AllowDropBox", "AllowBox", "AllowGoogleDrive", "AllowShareFile", "AllowEgnyte"]

# Every rule below compares a field only when it has the type the rule expects
# and iterates a list only when it is a list; a missing field or a wrong shape
# leaves the control out of `decidable`, and the evidence rules at the end of
# the file report it by id. It is never read as a pass or as a failure.

default unavailable := {}

unavailable := input.teams.unavailable if is_object(input.teams.unavailable)

default collected := false

collected if {
	input.teams.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

_object(key) := input.teams[key] if {
	available(key)
	is_object(input.teams[key])
}

_list(key) := input.teams[key] if {
	available(key)
	is_array(input.teams[key])
}

client_config := _object("client_configuration")

federation := _object("federation_configuration")

meeting_policies := _list("meeting_policies")

messaging_policies := _list("messaging_policies")

# ── CIS 8.1.1 -- external file sharing limited to approved services ──
violation contains msg if {
	some field in APPROVED_STORAGE_FIELDS
	client_config[field] == true
	msg := sprintf("CIS 8.1.1: external file sharing in Teams permits '%s'; only approved cloud storage services should be enabled", [field])
}

# ── CIS 8.1.2 -- email into channel ──────────────────────────────────
violation contains msg if {
	client_config.AllowEmailIntoChannel == true
	msg := "CIS 8.1.2: users can send emails to a channel email address, which accepts mail from outside the tenant into a Teams channel"
}

# ── CIS 8.2.1 -- external domains restricted ─────────────────────────
# Compliant: federation off (AllowFederatedUsers False), or on with an allow
# list -- an empty allow list blocks every external domain, which is also
# compliant. Not compliant: AllowAllKnownDomains (every domain not on the
# block list). AllowedDomains is an IAllowedDomainsChoice object, an AllowList
# (property AllowedDomain) or AllowAllKnownDomains, not a list of strings.
# https://learn.microsoft.com/en-us/powershell/module/teams/set-cstenantfederationconfiguration
# Read here: the string "AllowAllKnownDomains", an object carrying an
# AllowAllKnownDomains key, an object carrying AllowedDomain (an allow list),
# or a plain list of domains (an allow list, as -AllowedDomainsAsAList sets
# it). Anything else -- null, an empty object, another string -- cannot be told
# apart and is evidence missing. Not read: the Global external access policy
# (Get-CsExternalAccessPolicy EnableFederationAccess), the benchmark's
# alternative passing state.
_domains_choice(v) := "open" if {
	is_string(v)
	lower(v) == "allowallknowndomains"
}

_domains_choice(v) := "open" if {
	is_object(v)
	"AllowAllKnownDomains" in object.keys(v)
	not "AllowedDomain" in object.keys(v)
}

_domains_choice(v) := "allow_list" if {
	is_object(v)
	"AllowedDomain" in object.keys(v)
	not "AllowAllKnownDomains" in object.keys(v)
}

_domains_choice(v) := "allow_list" if is_array(v)

violation contains msg if {
	federation.AllowFederatedUsers == true
	_domains_choice(object.get(federation, "AllowedDomains", null)) == "open"
	msg := "CIS 8.2.1: external domains are not restricted in the Teams admin center -- federation is open to every known domain rather than an allow list"
}

# ── CIS 8.2.2 -- communication with unmanaged Teams users ────────────
violation contains msg if {
	federation.AllowTeamsConsumer == true
	msg := "CIS 8.2.2: communication with unmanaged Teams users is not disabled, so staff can be contacted by personal Teams accounts"
}

# ── CIS 8.2.3 -- external users initiating conversations ─────────────
violation contains msg if {
	federation.AllowTeamsConsumerInbound == true
	msg := "CIS 8.2.3: external Teams users can initiate conversations; inbound contact from unmanaged accounts should be blocked"
}

# ── CIS 8.2.4 -- trial tenants ───────────────────────────────────────
violation contains msg if {
	federation.ExternalAccessWithTrialTenants == "Allowed"
	msg := "CIS 8.2.4: the organization can communicate with accounts in trial Teams tenants, which are trivially created and commonly used for impersonation"
}

# ── Meeting policies (8.5.1 through 8.5.9) ───────────────────────────
violation contains msg if {
	some p in meeting_policies
	p.AllowAnonymousUsersToJoinMeeting == true
	msg := sprintf("CIS 8.5.1: meeting policy '%s' lets anonymous users join a meeting", [object.get(p, "Identity", "(unnamed)")])
}

violation contains msg if {
	some p in meeting_policies
	p.AllowAnonymousUsersToStartMeeting == true
	msg := sprintf("CIS 8.5.2: meeting policy '%s' lets anonymous users and dial-in callers start a meeting, so a meeting can run with no organizer present", [object.get(p, "Identity", "(unnamed)")])
}

violation contains msg if {
	some p in meeting_policies
	is_string(p.AutoAdmittedUsers)
	not p.AutoAdmittedUsers in {"EveryoneInCompany", "EveryoneInCompanyExcludingGuests", "InvitedUsers", "OrganizerOnly"}
	msg := sprintf("CIS 8.5.3: meeting policy '%s' admits '%s' automatically; only people in the org should bypass the lobby", [object.get(p, "Identity", "(unnamed)"), p.AutoAdmittedUsers])
}

violation contains msg if {
	some p in meeting_policies
	p.AllowPSTNUsersToBypassLobby == true
	msg := sprintf("CIS 8.5.4: meeting policy '%s' lets users dialing in bypass the lobby", [object.get(p, "Identity", "(unnamed)")])
}

violation contains msg if {
	some p in meeting_policies
	p.MeetingChatEnabledType == "Enabled"
	msg := sprintf("CIS 8.5.5: meeting policy '%s' allows meeting chat for anonymous users", [object.get(p, "Identity", "(unnamed)")])
}

violation contains msg if {
	some p in meeting_policies
	is_string(p.DesignatedPresenterRoleMode)
	p.DesignatedPresenterRoleMode != "OrganizerOnlyUserOverride"
	msg := sprintf("CIS 8.5.6: meeting policy '%s' does not restrict presenting to organizers and co-organizers", [object.get(p, "Identity", "(unnamed)")])
}

violation contains msg if {
	some p in meeting_policies
	p.AllowExternalParticipantGiveRequestControl == true
	msg := sprintf("CIS 8.5.7: meeting policy '%s' lets external participants give or request control of a shared screen", [object.get(p, "Identity", "(unnamed)")])
}

violation contains msg if {
	some p in meeting_policies
	p.AllowExternalNonTrustedMeetingChat == true
	msg := sprintf("CIS 8.5.8: meeting policy '%s' leaves external meeting chat on", [object.get(p, "Identity", "(unnamed)")])
}

violation contains msg if {
	some p in meeting_policies
	p.AllowCloudRecording == true
	msg := sprintf("CIS 8.5.9: meeting policy '%s' has meeting recording on by default", [object.get(p, "Identity", "(unnamed)")])
}

# ── CIS 8.6.1 -- users can report security concerns ──────────────────
violation contains msg if {
	some p in messaging_policies
	p.AllowSecurityEndUserReporting == false
	msg := sprintf("CIS 8.6.1: messaging policy '%s' does not let users report security concerns in Teams, removing the reporting path for suspicious messages", [object.get(p, "Identity", "(unnamed)")])
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
	"evidence_strength": {"section": "collected with the cmdlets CIS documents (Get-CsTeamsClientConfiguration, Get-CsTenantFederationConfiguration, Get-CsTeamsMeetingPolicy, Get-CsTeamsMessagingPolicy), all verified present in the execution environment. Meeting and messaging policies are evaluated across ALL policies, not only Global, because a permissive non-global policy still governs the users it is assigned to."},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

# ── Per-control results ──────────────────────────────────────────────
# `decidable` holds the controls of this section whose facts were all
# collected; CONTROL_EVIDENCE names the input paths each one reads ("[]"
# = every element of a list). A control that is not decidable is reported
# by id as evidence missing (rules at the end of the file) and the main
# report marks it "evidence_missing": an absent fact must never read as a
# pass. Each gate restates the condition of its rule above; change them
# together.
MEETING_POLICY_FIELDS := {
	"8.5.1": "AllowAnonymousUsersToJoinMeeting",
	"8.5.2": "AllowAnonymousUsersToStartMeeting",
	"8.5.3": "AutoAdmittedUsers",
	"8.5.4": "AllowPSTNUsersToBypassLobby",
	"8.5.5": "MeetingChatEnabledType",
	"8.5.6": "DesignatedPresenterRoleMode",
	"8.5.7": "AllowExternalParticipantGiveRequestControl",
	"8.5.8": "AllowExternalNonTrustedMeetingChat",
	"8.5.9": "AllowCloudRecording",
}

# the meeting-policy fields that are enum strings; the others are booleans
STRING_FIELDS := {"AutoAdmittedUsers", "MeetingChatEnabledType", "DesignatedPresenterRoleMode", "ExternalAccessWithTrialTenants"}

FEDERATION_FIELDS := {
	"8.2.1": "AllowFederatedUsers",
	"8.2.2": "AllowTeamsConsumer",
	"8.2.3": "AllowTeamsConsumerInbound",
	"8.2.4": "ExternalAccessWithTrialTenants",
}

_typed(v, field) if {
	field in STRING_FIELDS
	is_string(v)
}

_typed(v, field) if {
	not field in STRING_FIELDS
	is_boolean(v)
}

_meeting_evidence := {id: [path] |
	some id, field in MEETING_POLICY_FIELDS
	path := concat(".", ["teams", "meeting_policies[]", field])
}

_federation_evidence := {id: paths |
	some id, field in FEDERATION_FIELDS
	paths := _federation_paths(id, field)
}

_federation_paths("8.2.1", field) := ["teams.federation_configuration.AllowedDomains", concat(".", ["teams", "federation_configuration", field])]

_federation_paths(id, field) := [concat(".", ["teams", "federation_configuration", field])] if id != "8.2.1"

CONTROL_EVIDENCE := object.union(object.union(_meeting_evidence, _federation_evidence), {
	"8.1.1": [concat(".", ["teams", "client_configuration", f]) | some f in APPROVED_STORAGE_FIELDS],
	"8.1.2": ["teams.client_configuration.AllowEmailIntoChannel"],
	"8.6.1": ["teams.messaging_policies[].AllowSecurityEndUserReporting"],
})

decidable contains "8.1.1" if {
	every field in APPROVED_STORAGE_FIELDS {
		is_boolean(client_config[field])
	}
}

decidable contains "8.1.2" if is_boolean(client_config.AllowEmailIntoChannel)

decidable contains id if {
	some id, field in FEDERATION_FIELDS
	id != "8.2.1"
	_typed(federation[field], field)
}

decidable contains "8.2.1" if federation.AllowFederatedUsers == false

decidable contains "8.2.1" if {
	federation.AllowFederatedUsers == true
	_domains_choice(object.get(federation, "AllowedDomains", null))
}

decidable contains id if {
	some id, field in MEETING_POLICY_FIELDS
	every p in meeting_policies {
		_typed(object.get(p, field, null), field)
	}
}

decidable contains "8.6.1" if {
	every p in messaging_policies {
		is_boolean(p.AllowSecurityEndUserReporting)
	}
}

# ── Evidence gaps, reported by control id ─────────────────────────────
# A gap names every control it blocks, so the per-control results and an
# exporter reading the ids agree on what was not evaluated. A key this module
# does not know is reported on its own, attributed to no control.
FACT_CONTROLS := {
	"client_configuration": ["8.1.1", "8.1.2"],
	"federation_configuration": ["8.2.1", "8.2.2", "8.2.3", "8.2.4"],
	"meeting_policies": ["8.5.1", "8.5.2", "8.5.3", "8.5.4", "8.5.5", "8.5.6", "8.5.7", "8.5.8", "8.5.9"],
	"messaging_policies": ["8.6.1"],
}

_section_controls := _natural_sort(object.keys(CONTROL_EVIDENCE))

# ids in benchmark order
_natural_sort(ids) := [pair[1] | some pair in sort([[key, id] |
	some id in ids
	parts := split(id, ".")
	key := concat(".", [sprintf("%03d", [to_number(x)]) | some x in parts])
])]

_gap(ids, why) := sprintf("CIS %s: evidence missing -- %s (this is not a pass)", [concat("/", ids), why])

_source_gaps contains [_section_controls, "Teams facts were not collected (teams.collected is not true)"] if not collected

_source_gaps contains [FACT_CONTROLS[key], sprintf("teams.unavailable.%s: %v", [key, reason])] if {
	collected
	some key, reason in unavailable
}

_gap_ids contains id if {
	some g in _source_gaps
	some id in g[0]
}

# a source gap names each control it leaves undecided in a message of its own, so the
# violation count is never smaller than the number of controls that are not a pass
_evidence_gaps contains _gap([id], concat("; ", sort(whys))) if {
	some id in _gap_ids
	not id in decidable
	whys := {g[1] | some g in _source_gaps; id in g[0]}
}

_evidence_gaps contains msg if {
	some key, reason in unavailable
	not FACT_CONTROLS[key]
	msg := sprintf("M365 section 8 (Teams): unrecognised unavailable key '%s' (%v) -- this module reads no fact of that name, so it is attributed to no control (this is not a pass)", [key, reason])
}

_evidence_gaps contains _gap([id], why) if {
	some id, paths in CONTROL_EVIDENCE
	not id in decidable
	not id in _gap_ids
	why := sprintf("%s not collected or not of the expected type", [concat(", ", paths)])
}

violation contains msg if some msg in _evidence_gaps
