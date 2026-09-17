# CISA SCuBA — Secure Configuration Baseline for SharePoint Online and
# OneDrive — 8 policies (MS.SHAREPOINT.*), all SHALL, per
# cisagov/ScubaGear (TLP:CLEAR).
#
# Input contract — input.scuba.sharepoint.* (source: SharePoint admin
# API / Get-SPOTenant; absence fails closed):
#
#   external_sharing.{spo_restricted, odb_restricted, domain_allowlist}
#                                              MS.SHAREPOINT.1.1-1.3
#   default_sharing.{scope_specific_people, permission_view_only}
#                                              MS.SHAREPOINT.2.1-2.2
#   anyone_links.{expiration_days, view_only}  MS.SHAREPOINT.3.1-3.2
#   verification_code_reauth_days              MS.SHAREPOINT.3.3
#
# OPA query path (module): /v1/data/scuba_m365/sharepoint/compliance_report

package scuba_m365.sharepoint

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Group 1 — External Sharing ───────────────────────────────────────────────

violations contains msg if {
	not input.scuba.sharepoint.external_sharing.spo_restricted
	msg := "SCuBA MS.SHAREPOINT.1.1v1 (SHALL): SharePoint external sharing is not limited to 'Existing guests' or 'Only people in your organization'"
}

violations contains msg if {
	not input.scuba.sharepoint.external_sharing.odb_restricted
	msg := "SCuBA MS.SHAREPOINT.1.2v1 (SHALL): OneDrive external sharing is not limited to 'Existing guests' or 'Only people in your organization'"
}

violations contains msg if {
	not input.scuba.sharepoint.external_sharing.domain_allowlist
	msg := "SCuBA MS.SHAREPOINT.1.3v1 (SHALL): External sharing is not restricted to approved external domains and/or security groups"
}

# ── Group 2 — Default Sharing Settings ───────────────────────────────────────

violations contains msg if {
	not input.scuba.sharepoint.default_sharing.scope_specific_people
	msg := "SCuBA MS.SHAREPOINT.2.1v1 (SHALL): File and folder default sharing scope is not 'Specific people'"
}

violations contains msg if {
	not input.scuba.sharepoint.default_sharing.permission_view_only
	msg := "SCuBA MS.SHAREPOINT.2.2v1 (SHALL): File and folder default sharing permission is not view-only"
}

# ── Group 3 — Anyone Links and Verification Code Users ───────────────────────

default anyone_link_expiration_ok := false

anyone_link_expiration_ok if {
	d := input.scuba.sharepoint.anyone_links.expiration_days
	d >= 1
	d <= 30
}

violations contains msg if {
	not anyone_link_expiration_ok
	msg := "SCuBA MS.SHAREPOINT.3.1v1 (SHALL): Anyone-link expiration is not set to 30 days or less"
}

violations contains msg if {
	not input.scuba.sharepoint.anyone_links.view_only
	msg := "SCuBA MS.SHAREPOINT.3.2v1 (SHALL): Anyone-link file and folder permissions are not restricted to view-only"
}

default verification_reauth_ok := false

verification_reauth_ok if {
	d := input.scuba.sharepoint.verification_code_reauth_days
	d >= 1
	d <= 30
}

violations contains msg if {
	not verification_reauth_ok
	msg := "SCuBA MS.SHAREPOINT.3.3v2 (SHALL): Verification-code reauthentication is not set to 30 days or less"
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

compliance_report := {
	"product": "SharePoint Online and OneDrive",
	"baseline": "MS.SHAREPOINT",
	"controls_evaluated": 8,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
