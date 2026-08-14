# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 7 -- SharePoint admin center
#
# Input contract (from the aac.m365 collection, /admin/sharepoint/settings):
#   input.sharepoint.sharing_capability          - str
#   input.sharepoint.default_sharing_link_type   - str
#   input.sharepoint.default_link_permission     - str
#   input.sharepoint.legacy_auth_protocols_enabled - bool
#   input.sharepoint.settings_reachable          - bool

package cis_m365_v7.sharepoint

import rego.v1

default compliant := false

default facts_present := false

facts_present if {
	input.sharepoint.settings_reachable == true
}

# CIS 7.2.1 -- modern authentication required for SharePoint applications.
violation contains msg if {
	facts_present
	input.sharepoint.legacy_auth_protocols_enabled == true
	msg := "CIS 7.2.1: legacy authentication protocols are permitted for SharePoint applications; modern authentication is not required, so clients can bypass Conditional Access"
}

# CIS 7.2.6 -- SharePoint external sharing must be restricted. The most
# permissive setting allows sharing with anonymous external users.
violation contains msg if {
	facts_present
	input.sharepoint.sharing_capability == "ExternalUserAndGuestSharing"
	msg := "CIS 7.2.6: SharePoint external sharing is set to the most permissive value (ExternalUserAndGuestSharing); restrict to ExistingExternalUserSharingOnly or Disabled"
}

# CIS 7.2.7 -- link sharing must be restricted in SharePoint and OneDrive.
violation contains msg if {
	facts_present
	input.sharepoint.default_sharing_link_type == "AnonymousAccess"
	msg := "CIS 7.2.7: the default sharing link is anonymous, so newly created links are world-readable; restrict link sharing to specific people or the organization"
}

# CIS 7.2.11 -- the default sharing link permission should be view, not edit.
violation contains msg if {
	facts_present
	input.sharepoint.default_link_permission == "Edit"
	msg := "CIS 7.2.11: the SharePoint default sharing link permission grants Edit; a default of View limits accidental modification by recipients"
}

violation contains msg if {
	not facts_present
	msg := "CIS 7.2.1: SharePoint tenant settings were not reachable -- external sharing and authentication controls could not be evaluated (this is not a pass)"
}

compliant if {
	facts_present
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "7",
	"name": "SharePoint admin center",
	"section_total_controls": 12,
	"controls_evaluated": 4,
	"controls": ["7.2.1", "7.2.6", "7.2.7", "7.2.11"],
	"facts_present": facts_present,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
