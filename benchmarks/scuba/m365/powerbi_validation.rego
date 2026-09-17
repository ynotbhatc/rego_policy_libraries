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

package scuba_m365.powerbi

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations contains msg if {
	not input.scuba.powerbi.publish_to_web_disabled
	msg := "SCuBA MS.POWERBI.1.1v1 (SHOULD): Publish to Web is not disabled"
}

violations contains msg if {
	not input.scuba.powerbi.guest_access_disabled
	msg := "SCuBA MS.POWERBI.2.1v1 (SHOULD): Guest user access to the Power BI tenant is not disabled"
}

violations contains msg if {
	not input.scuba.powerbi.external_invitations_disabled
	msg := "SCuBA MS.POWERBI.3.1v1 (SHOULD): 'Invite external users to your organization' is not disabled"
}

violations contains msg if {
	not input.scuba.powerbi.service_principals.api_restricted_to_groups
	msg := "SCuBA MS.POWERBI.4.1v1 (SHOULD): Service principals with API access are not restricted to specific security groups"
}

violations contains msg if {
	not input.scuba.powerbi.service_principals.profiles_restricted_to_groups
	msg := "SCuBA MS.POWERBI.4.2v1 (SHOULD): Service principals creating and using profiles are not restricted to specific security groups"
}

violations contains msg if {
	not input.scuba.powerbi.resourcekey_auth_blocked
	msg := "SCuBA MS.POWERBI.5.1v1 (SHOULD): ResourceKey-based authentication is not blocked"
}

violations contains msg if {
	not input.scuba.powerbi.python_r_interactions_disabled
	msg := "SCuBA MS.POWERBI.6.1v1 (SHOULD): Python and R visual interactions are not disabled"
}

violations contains msg if {
	not input.scuba.powerbi.sensitivity_labels_enabled
	msg := "SCuBA MS.POWERBI.7.1v1 (SHOULD): Sensitivity labels are not enabled for Power BI sensitive data"
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
