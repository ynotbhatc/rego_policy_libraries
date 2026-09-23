# UK Cyber Essentials — master orchestrator
#
# Aggregates the five Cyber Essentials technical control themes (Willow
# question set, effective April 2025) into one compliance report with a
# per-theme rollup. Cyber Essentials has no maturity tiers — straight
# fail-closed requirement pass/fail. Cyber Essentials Plus verifies the same
# controls by independent technical audit; this module models the control
# requirements, not the certification route. Fail-closed: an unattested
# requirement is a gap.
#
# Entry point: data.cyber_essentials.main.compliance_report

package cyber_essentials.main

import rego.v1

import data.cyber_essentials.firewalls
import data.cyber_essentials.malware_protection
import data.cyber_essentials.secure_configuration
import data.cyber_essentials.security_update_management
import data.cyber_essentials.user_access_control

# Per-theme reports, in Cyber Essentials control-theme order.
theme_reports := [
	firewalls.compliance_report,
	secure_configuration.compliance_report,
	security_update_management.compliance_report,
	user_access_control.compliance_report,
	malware_protection.compliance_report,
]

all_violations := [v | some r in theme_reports; some v in r.violations]

# Attestation object for a theme, defaulted to {} so the report is robust to
# entirely-absent input (the standard bare `opa eval` verify command) and to
# a malformed non-object `requirements` value, which would otherwise make
# object.get undefined and silently drop the theme's ids from _all.
default _attest(_) := {}

_attest(theme) := req if {
	req := input.cyber_essentials[theme].requirements
	is_object(req)
}

_specs := [
	{"key": "firewalls", "req": firewalls.requirements},
	{"key": "secure_configuration", "req": secure_configuration.requirements},
	{"key": "security_update_management", "req": security_update_management.requirements},
	{"key": "user_access_control", "req": user_access_control.requirements},
	{"key": "malware_protection", "req": malware_protection.requirements},
]

# id -> {theme, met}. Requirement ids are unique across themes (distinct prefixes).
_all[id] := {"theme": m.theme, "met": object.get(_attest(spec.key), id, false) == true} if {
	some spec in _specs
	some id, m in spec.req
}

total_requirements := count(_all)

requirements_met := count([id | some id, c in _all; c.met])

# Per-theme rollup, keyed by theme name.
control_themes[name] := {
	"theme": r.theme,
	"requirements": r.requirements_evaluated,
	"gaps": r.violation_count,
	"compliant": r.compliant,
} if {
	some r in theme_reports
	name := r.area_name
}

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"framework": "UK Cyber Essentials (Willow question set, April 2025)",
	"reference": "NCSC Cyber Essentials Requirements for IT infrastructure",
	"themes_evaluated": count(theme_reports),
	"total_requirements": total_requirements,
	"requirements_met": requirements_met,
	"control_themes": control_themes,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"compliant": compliant,
}
