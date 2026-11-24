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

# METADATA
# title: "CISA SCuBA — Secure Configuration Baseline for SharePoint Online and OneDrive — 8 policies (MS.SHAREPOINT.*), all SHALL, per"
# custom:
#   class: security
#   framework: scuba_m365
#   source: cisa
#   domains: [saas, m365]
#   coverage:
#     checks: 8
#     cited: 8
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package scuba_m365.sharepoint

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

# a numeric fact: the finding as written when it is a number, the evidence wording otherwise
_num_finding(text, path) := text if is_number(object.get(input, path, null))

_num_finding(text, path) := sprintf("%s evidence missing — input.%s not collected", [_policy(text), concat(".", path)]) if {
	not _collected(path)
}

_num_finding(text, path) := sprintf("%s evidence invalid — input.%s must be a number, got %s", [_policy(text), concat(".", path), json.marshal(v)]) if {
	_collected(path)
	v := object.get(input, path, null)
	not is_number(v)
}

# present, including present as null
_collected(path) if {
	parent := object.get(input, array.slice(path, 0, count(path) - 1), null)
	is_object(parent)
	path[count(path) - 1] in object.keys(parent)
}

# "SCuBA MS.X.1.1v1 (SHALL):" from the finding text
_policy(text) := concat("", [split(text, "): ")[0], "):"])

# ── Group 1 — External Sharing ───────────────────────────────────────────────

violations contains msg if {
	not input.scuba.sharepoint.external_sharing.spo_restricted == true
	text := "SCuBA MS.SHAREPOINT.1.1v1 (SHALL): SharePoint external sharing is not limited to 'Existing guests' or 'Only people in your organization'"
	msg := _finding(text, ["scuba", "sharepoint", "external_sharing", "spo_restricted"])
}

violations contains msg if {
	not input.scuba.sharepoint.external_sharing.odb_restricted == true
	text := "SCuBA MS.SHAREPOINT.1.2v1 (SHALL): OneDrive external sharing is not limited to 'Existing guests' or 'Only people in your organization'"
	msg := _finding(text, ["scuba", "sharepoint", "external_sharing", "odb_restricted"])
}

violations contains msg if {
	not input.scuba.sharepoint.external_sharing.domain_allowlist == true
	text := "SCuBA MS.SHAREPOINT.1.3v1 (SHALL): External sharing is not restricted to approved external domains and/or security groups"
	msg := _finding(text, ["scuba", "sharepoint", "external_sharing", "domain_allowlist"])
}

# ── Group 2 — Default Sharing Settings ───────────────────────────────────────

violations contains msg if {
	not input.scuba.sharepoint.default_sharing.scope_specific_people == true
	text := "SCuBA MS.SHAREPOINT.2.1v1 (SHALL): File and folder default sharing scope is not 'Specific people'"
	msg := _finding(text, ["scuba", "sharepoint", "default_sharing", "scope_specific_people"])
}

violations contains msg if {
	not input.scuba.sharepoint.default_sharing.permission_view_only == true
	text := "SCuBA MS.SHAREPOINT.2.2v1 (SHALL): File and folder default sharing permission is not view-only"
	msg := _finding(text, ["scuba", "sharepoint", "default_sharing", "permission_view_only"])
}

# ── Group 3 — Anyone Links and Verification Code Users ───────────────────────

default anyone_link_expiration_ok := false

anyone_link_expiration_ok if {
	d := input.scuba.sharepoint.anyone_links.expiration_days
	is_number(d)
	d >= 1
	d <= 30
}

violations contains msg if {
	not anyone_link_expiration_ok
	text := "SCuBA MS.SHAREPOINT.3.1v1 (SHALL): Anyone-link expiration is not set to 30 days or less"
	msg := _num_finding(text, ["scuba", "sharepoint", "anyone_links", "expiration_days"])
}

violations contains msg if {
	not input.scuba.sharepoint.anyone_links.view_only == true
	text := "SCuBA MS.SHAREPOINT.3.2v1 (SHALL): Anyone-link file and folder permissions are not restricted to view-only"
	msg := _finding(text, ["scuba", "sharepoint", "anyone_links", "view_only"])
}

default verification_reauth_ok := false

verification_reauth_ok if {
	d := input.scuba.sharepoint.verification_code_reauth_days
	is_number(d)
	d >= 1
	d <= 30
}

violations contains msg if {
	not verification_reauth_ok
	text := "SCuBA MS.SHAREPOINT.3.3v2 (SHALL): Verification-code reauthentication is not set to 30 days or less"
	msg := _num_finding(text, ["scuba", "sharepoint", "verification_code_reauth_days"])
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
