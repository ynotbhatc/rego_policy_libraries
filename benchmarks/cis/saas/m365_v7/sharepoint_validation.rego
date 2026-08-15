# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 7 -- SharePoint admin center
#
# All 12 of section 7's recommendations are evaluated here, from a single
# tenant object.
#
# DELIBERATE, PERMANENT DEVIATION FROM THE BENCHMARK'S PROCEDURE:
# CIS audits these with Get-SPOTenant, which lives in
# Microsoft.Online.SharePoint.PowerShell -- a Windows-only module that
# cannot be installed in a Linux execution environment (verified absent
# from aac-m365-ee). Facts come from Get-PnPTenant instead, which reads
# the same CSOM tenant properties. Values are equivalent; the tool is not
# the one CIS documents, so the report carries an evidence note for the
# whole section rather than implying the benchmark's own procedure was
# followed.
#
# This also SUPERSEDES the previous Graph-based evaluation of 7.2.1,
# 7.2.6, 7.2.7 and 7.2.11 via /admin/sharepoint/settings. Those reached
# the right answer by a path CIS does not document at all; the tenant
# properties below are at least the same underlying settings CIS reads.
#
# Input contract (aac.m365.m365_sharepoint_ps_facts):
#   input.sharepoint.tenant              - the collected tenant properties
#   input.sharepoint.missing_properties[] - expected properties ABSENT from
#                                           the object (fail closed on these)
#   input.sharepoint.unavailable         - {key: reason}

package cis_m365_v7.sharepoint

import rego.v1

default compliant := false

# Sharing capability values, most to least permissive. The benchmark wants
# anything other than the fully-external settings.
PERMISSIVE_SHARING := {"ExternalUserAndGuestSharing", "ExistingExternalUserSharingOnly"}
ANONYMOUS_SHARING := "ExternalUserAndGuestSharing"

default unavailable := {}

unavailable := input.sharepoint.unavailable

default collected := false

collected if {
	input.sharepoint.collected == true
}

tenant := object.get(input, ["sharepoint", "tenant"], {})

# A control is evaluable only when the collector actually returned the
# property it depends on. A property that PnP did not return is recorded
# by the collector, so a renamed or wrong property name fails closed here
# rather than reading as null and passing.
available(prop) if {
	collected
	not unavailable[prop]
	_ := tenant[prop]
}

# ── CIS 7.2.1 -- modern authentication required ──────────────────────
violation contains msg if {
	available("LegacyAuthProtocolsEnabled")
	tenant.LegacyAuthProtocolsEnabled == true
	msg := "CIS 7.2.1: legacy authentication protocols are permitted, so modern authentication is not required for SharePoint applications and clients can bypass Conditional Access"
}

# ── CIS 7.2.2 -- Azure AD B2B integration ────────────────────────────
violation contains msg if {
	available("EnableAzureADB2BIntegration")
	tenant.EnableAzureADB2BIntegration == false
	msg := "CIS 7.2.2: SharePoint and OneDrive integration with Azure AD B2B is not enabled, so external guests are not governed by Entra guest identities"
}

# ── CIS 7.2.3 / 7.2.6 -- external and SharePoint sharing ─────────────
violation contains msg if {
	available("SharingCapability")
	tenant.SharingCapability == ANONYMOUS_SHARING
	msg := "CIS 7.2.3: external content sharing is set to the most permissive value (ExternalUserAndGuestSharing), which allows anonymous links"
}

violation contains msg if {
	available("SharingCapability")
	tenant.SharingCapability in PERMISSIVE_SHARING
	msg := sprintf("CIS 7.2.6: SharePoint external sharing is '%s'; restrict it to New and existing guests or Only people in your organization", [tenant.SharingCapability])
}

# ── CIS 7.2.4 -- OneDrive sharing ────────────────────────────────────
violation contains msg if {
	available("OneDriveSharingCapability")
	tenant.OneDriveSharingCapability in PERMISSIVE_SHARING
	msg := sprintf("CIS 7.2.4: OneDrive content sharing is '%s' and is not restricted; OneDrive inherits the tenant default unless set separately", [tenant.OneDriveSharingCapability])
}

# ── CIS 7.2.5 -- guests resharing items they do not own ──────────────
violation contains msg if {
	available("PreventExternalUsersFromResharing")
	tenant.PreventExternalUsersFromResharing == false
	msg := "CIS 7.2.5: SharePoint guest users can share items they don't own, so access granted to one external party can be forwarded to another"
}

# ── CIS 7.2.7 -- link sharing ────────────────────────────────────────
violation contains msg if {
	available("DefaultSharingLinkType")
	tenant.DefaultSharingLinkType == "AnonymousAccess"
	msg := "CIS 7.2.7: link sharing in SharePoint and OneDrive defaults to anonymous access, so newly created links are world-readable"
}

# ── CIS 7.2.8 -- sharing restricted by security group ────────────────
violation contains msg if {
	available("SharingDomainRestrictionMode")
	tenant.SharingDomainRestrictionMode == "None"
	msg := "CIS 7.2.8: external sharing is not restricted by security group or domain; any user may share with any external party"
}

# ── CIS 7.2.9 -- guest access expiry ─────────────────────────────────
violation contains msg if {
	available("ExternalUserExpirationRequired")
	tenant.ExternalUserExpirationRequired == false
	msg := "CIS 7.2.9: guest access to a site or OneDrive does not expire automatically, so external access persists indefinitely after a project ends"
}

# ── CIS 7.2.10 -- reauthentication with verification code ────────────
violation contains msg if {
	available("EmailAttestationRequired")
	tenant.EmailAttestationRequired == false
	msg := "CIS 7.2.10: reauthentication with a verification code is not restricted, so an external recipient's link stays valid without re-proving control of the mailbox"
}

# ── CIS 7.2.11 -- default sharing link permission ────────────────────
violation contains msg if {
	available("DefaultLinkPermission")
	tenant.DefaultLinkPermission == "Edit"
	msg := "CIS 7.2.11: the SharePoint default sharing link permission is set to Edit; a default of View limits accidental modification by recipients"
}

# ── CIS 7.3.1 -- infected file download ──────────────────────────────
violation contains msg if {
	available("DisallowInfectedFileDownload")
	tenant.DisallowInfectedFileDownload == false
	msg := "CIS 7.3.1: Office 365 SharePoint infected files are not disallowed for download, so a file Defender has flagged can still be retrieved"
}

# ── Fail closed ───────────────────────────────────────────────────────
# The collector records every expected-but-absent property, naming the
# controls it blocks. Surface each as its own violation.
PROPERTY_CONTROLS := {
	"LegacyAuthProtocolsEnabled": "7.2.1",
	"EnableAzureADB2BIntegration": "7.2.2",
	"SharingCapability": "7.2.3",
	"OneDriveSharingCapability": "7.2.4",
	"PreventExternalUsersFromResharing": "7.2.5",
	"DefaultSharingLinkType": "7.2.7",
	"SharingDomainRestrictionMode": "7.2.8",
	"ExternalUserExpirationRequired": "7.2.9",
	"EmailAttestationRequired": "7.2.10",
	"DefaultLinkPermission": "7.2.11",
	"DisallowInfectedFileDownload": "7.3.1",
	"tenant": "7.2.1",
}

violation contains msg if {
	some key, reason in unavailable
	control := object.get(PROPERTY_CONTROLS, key, "7.2.1")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not collected
	msg := "CIS 7.2.1: SharePoint tenant facts were not collected, so whether modern authentication is required could not be established -- section 7 was not evaluated (this is not a pass)"
}

compliant if {
	collected
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "7",
	"name": "SharePoint admin center",
	"section_total_controls": 12,
	"controls_evaluated": 12,
	"controls": [
		"7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.5", "7.2.6",
		"7.2.7", "7.2.8", "7.2.9", "7.2.10", "7.2.11", "7.3.1",
	],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	"evidence_strength": {
		"section": "collected with Get-PnPTenant, not the Get-SPOTenant the benchmark documents -- Microsoft.Online.SharePoint.PowerShell is Windows-only and cannot run in a Linux execution environment. The same CSOM tenant properties are read.",
	},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
