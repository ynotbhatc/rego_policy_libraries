# CISA SCuBA — Secure Configuration Baseline for Power Platform — 9
# policies (MS.POWERPLATFORM.*), per cisagov/ScubaGear (TLP:CLEAR).
#
# Input contract — input.scuba.powerplatform.* (source: Power Platform
# admin API / tenant settings; absence fails closed):
#
#   environment_creation.{production_restricted_to_admins,
#                         trial_restricted_to_admins}   MS.POWERPLATFORM.1.1-1.2
#   dlp.{default_environment_policy,
#        nondefault_environments_covered}               MS.POWERPLATFORM.2.1-2.2
#   tenant_isolation.{enabled, connection_allowlist}    MS.POWERPLATFORM.3.1-3.2
#   apps_csp_enforced                                   MS.POWERPLATFORM.4.1
#   power_pages_creation_restricted                     MS.POWERPLATFORM.5.1
#   share_with_everyone_disabled                        MS.POWERPLATFORM.6.1
#
# OPA query path (module): /v1/data/scuba_m365/powerplatform/compliance_report

package scuba_m365.powerplatform

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations contains msg if {
	not input.scuba.powerplatform.environment_creation.production_restricted_to_admins
	msg := "SCuBA MS.POWERPLATFORM.1.1v1 (SHALL): Creation of production and sandbox environments is not restricted to admins"
}

violations contains msg if {
	not input.scuba.powerplatform.environment_creation.trial_restricted_to_admins
	msg := "SCuBA MS.POWERPLATFORM.1.2v1 (SHALL): Creation of trial environments is not restricted to admins"
}

violations contains msg if {
	not input.scuba.powerplatform.dlp.default_environment_policy
	msg := "SCuBA MS.POWERPLATFORM.2.1v1 (SHALL): No DLP policy restricts connector access in the default environment"
}

violations contains msg if {
	not input.scuba.powerplatform.dlp.nondefault_environments_covered
	msg := "SCuBA MS.POWERPLATFORM.2.2v1 (SHOULD): Non-default environments are not covered by at least one DLP policy"
}

violations contains msg if {
	not input.scuba.powerplatform.tenant_isolation.enabled
	msg := "SCuBA MS.POWERPLATFORM.3.1v1 (SHALL): Power Platform tenant isolation is not enabled"
}

violations contains msg if {
	not input.scuba.powerplatform.tenant_isolation.connection_allowlist
	msg := "SCuBA MS.POWERPLATFORM.3.2v1 (SHOULD): No inbound/outbound cross-tenant connection allowlist is configured"
}

violations contains msg if {
	not input.scuba.powerplatform.apps_csp_enforced
	msg := "SCuBA MS.POWERPLATFORM.4.1v1 (SHALL): Content Security Policy is not enforced for model-driven and canvas Power Apps"
}

violations contains msg if {
	not input.scuba.powerplatform.power_pages_creation_restricted
	msg := "SCuBA MS.POWERPLATFORM.5.1v1 (SHOULD): Creation of Power Pages sites is not restricted to admins"
}

violations contains msg if {
	not input.scuba.powerplatform.share_with_everyone_disabled
	msg := "SCuBA MS.POWERPLATFORM.6.1v1 (SHOULD): The Power Apps 'Share with Everyone' capability is not disabled"
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

compliance_report := {
	"product": "Power Platform",
	"baseline": "MS.POWERPLATFORM",
	"controls_evaluated": 9,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
