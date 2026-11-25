# CISA SCuBA — Secure Configuration Baseline for Power BI — 8 policies
# (MS.POWERBI.*), per cisagov/ScubaGear (TLP:CLEAR). All eight are
# SHOULD-criticality: each carries an "unless the agency mission requires
# the capability" qualifier in the baseline, so an accepted-use decision
# belongs in the caller's exception process, not in this policy.
#
# Input contract — input.scuba.powerbi.* (source: Power BI admin tenant
# settings API; absence fails closed):
#
#   publish_to_web_disabled            MS.POWERBI.1.1
#   guest_access_disabled              MS.POWERBI.2.1
#   external_invitations_disabled      MS.POWERBI.3.1
#   service_principals.{api_restricted_to_groups,
#                       profiles_restricted_to_groups}  MS.POWERBI.4.1-4.2
#   resourcekey_auth_blocked           MS.POWERBI.5.1
#   python_r_interactions_disabled     MS.POWERBI.6.1
#   sensitivity_labels_enabled         MS.POWERBI.7.1
#
# OPA query path (module): /v1/data/scuba_m365/powerbi/compliance_report

# METADATA
# title: "CISA SCuBA — Secure Configuration Baseline for Power BI — 8 policies"
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
package scuba_m365.powerbi

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

violations contains msg if {
	not input.scuba.powerbi.publish_to_web_disabled == true
	text := "SCuBA MS.POWERBI.1.1v1 (SHOULD): Publish to Web is not disabled"
	msg := _finding(text, ["scuba", "powerbi", "publish_to_web_disabled"])
}

violations contains msg if {
	not input.scuba.powerbi.guest_access_disabled == true
	text := "SCuBA MS.POWERBI.2.1v1 (SHOULD): Guest user access to the Power BI tenant is not disabled"
	msg := _finding(text, ["scuba", "powerbi", "guest_access_disabled"])
}

violations contains msg if {
	not input.scuba.powerbi.external_invitations_disabled == true
	text := "SCuBA MS.POWERBI.3.1v1 (SHOULD): 'Invite external users to your organization' is not disabled"
	msg := _finding(text, ["scuba", "powerbi", "external_invitations_disabled"])
}

violations contains msg if {
	not input.scuba.powerbi.service_principals.api_restricted_to_groups == true
	text := "SCuBA MS.POWERBI.4.1v1 (SHOULD): Service principals with API access are not restricted to specific security groups"
	msg := _finding(text, ["scuba", "powerbi", "service_principals", "api_restricted_to_groups"])
}

violations contains msg if {
	not input.scuba.powerbi.service_principals.profiles_restricted_to_groups == true
	text := "SCuBA MS.POWERBI.4.2v1 (SHOULD): Service principals creating and using profiles are not restricted to specific security groups"
	msg := _finding(text, ["scuba", "powerbi", "service_principals", "profiles_restricted_to_groups"])
}

violations contains msg if {
	not input.scuba.powerbi.resourcekey_auth_blocked == true
	text := "SCuBA MS.POWERBI.5.1v1 (SHOULD): ResourceKey-based authentication is not blocked"
	msg := _finding(text, ["scuba", "powerbi", "resourcekey_auth_blocked"])
}

violations contains msg if {
	not input.scuba.powerbi.python_r_interactions_disabled == true
	text := "SCuBA MS.POWERBI.6.1v1 (SHOULD): Python and R visual interactions are not disabled"
	msg := _finding(text, ["scuba", "powerbi", "python_r_interactions_disabled"])
}

violations contains msg if {
	not input.scuba.powerbi.sensitivity_labels_enabled == true
	text := "SCuBA MS.POWERBI.7.1v1 (SHOULD): Sensitivity labels are not enabled for Power BI sensitive data"
	msg := _finding(text, ["scuba", "powerbi", "sensitivity_labels_enabled"])
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

compliance_report := {
	"product": "Power BI",
	"baseline": "MS.POWERBI",
	"controls_evaluated": 8,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
