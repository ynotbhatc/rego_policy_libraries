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

# METADATA
# title: "CISA SCuBA — Secure Configuration Baseline for Power Platform — 9"
# custom:
#   class: security
#   framework: scuba_m365
#   source: cisa
#   domains: [saas, m365]
#   coverage:
#     checks: 9
#     cited: 9
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package scuba_m365.powerplatform

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
	not input.scuba.powerplatform.environment_creation.production_restricted_to_admins == true
	text := "SCuBA MS.POWERPLATFORM.1.1v1 (SHALL): Creation of production and sandbox environments is not restricted to admins"
	msg := _finding(text, ["scuba", "powerplatform", "environment_creation", "production_restricted_to_admins"])
}

violations contains msg if {
	not input.scuba.powerplatform.environment_creation.trial_restricted_to_admins == true
	text := "SCuBA MS.POWERPLATFORM.1.2v1 (SHALL): Creation of trial environments is not restricted to admins"
	msg := _finding(text, ["scuba", "powerplatform", "environment_creation", "trial_restricted_to_admins"])
}

violations contains msg if {
	not input.scuba.powerplatform.dlp.default_environment_policy == true
	text := "SCuBA MS.POWERPLATFORM.2.1v1 (SHALL): No DLP policy restricts connector access in the default environment"
	msg := _finding(text, ["scuba", "powerplatform", "dlp", "default_environment_policy"])
}

violations contains msg if {
	not input.scuba.powerplatform.dlp.nondefault_environments_covered == true
	text := "SCuBA MS.POWERPLATFORM.2.2v1 (SHOULD): Non-default environments are not covered by at least one DLP policy"
	msg := _finding(text, ["scuba", "powerplatform", "dlp", "nondefault_environments_covered"])
}

violations contains msg if {
	not input.scuba.powerplatform.tenant_isolation.enabled == true
	text := "SCuBA MS.POWERPLATFORM.3.1v1 (SHALL): Power Platform tenant isolation is not enabled"
	msg := _finding(text, ["scuba", "powerplatform", "tenant_isolation", "enabled"])
}

violations contains msg if {
	not input.scuba.powerplatform.tenant_isolation.connection_allowlist == true
	text := "SCuBA MS.POWERPLATFORM.3.2v1 (SHOULD): No inbound/outbound cross-tenant connection allowlist is configured"
	msg := _finding(text, ["scuba", "powerplatform", "tenant_isolation", "connection_allowlist"])
}

violations contains msg if {
	not input.scuba.powerplatform.apps_csp_enforced == true
	text := "SCuBA MS.POWERPLATFORM.4.1v1 (SHALL): Content Security Policy is not enforced for model-driven and canvas Power Apps"
	msg := _finding(text, ["scuba", "powerplatform", "apps_csp_enforced"])
}

violations contains msg if {
	not input.scuba.powerplatform.power_pages_creation_restricted == true
	text := "SCuBA MS.POWERPLATFORM.5.1v1 (SHOULD): Creation of Power Pages sites is not restricted to admins"
	msg := _finding(text, ["scuba", "powerplatform", "power_pages_creation_restricted"])
}

violations contains msg if {
	not input.scuba.powerplatform.share_with_everyone_disabled == true
	text := "SCuBA MS.POWERPLATFORM.6.1v1 (SHOULD): The Power Apps 'Share with Everyone' capability is not disabled"
	msg := _finding(text, ["scuba", "powerplatform", "share_with_everyone_disabled"])
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
