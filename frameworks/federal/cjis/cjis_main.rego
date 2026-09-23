# FBI CJIS Security Policy — master orchestrator
#
# Aggregates the 13 CJIS Policy Areas into one compliance report with a
# per-policy-area rollup. CJIS has no maturity tiers — straight fail-closed
# requirement pass/fail. Requirements map to NIST SP 800-53. Fail-closed: an
# unattested requirement is a gap.
#
# Entry point: data.cjis.main.compliance_report

package cjis.main

import rego.v1

import data.cjis.access_control
import data.cjis.auditing_accountability
import data.cjis.configuration_management
import data.cjis.formal_audits
import data.cjis.identification_authentication
import data.cjis.incident_response
import data.cjis.information_exchange
import data.cjis.media_protection
import data.cjis.mobile_devices
import data.cjis.personnel_security
import data.cjis.physical_protection
import data.cjis.security_awareness_training
import data.cjis.systems_communications_protection

# Per-policy-area reports, in CJIS policy-area order.
area_reports := [
	information_exchange.compliance_report,
	security_awareness_training.compliance_report,
	incident_response.compliance_report,
	auditing_accountability.compliance_report,
	access_control.compliance_report,
	identification_authentication.compliance_report,
	configuration_management.compliance_report,
	media_protection.compliance_report,
	physical_protection.compliance_report,
	systems_communications_protection.compliance_report,
	formal_audits.compliance_report,
	personnel_security.compliance_report,
	mobile_devices.compliance_report,
]

all_violations := [v | some r in area_reports; some v in r.violations]

# Attestation object for a policy area, defaulted to {} so the report is robust
# to entirely-absent input (the standard bare `opa eval` verify command).
default _attest(_) := {}

_attest(area) := req if {
	req := input.cjis[area].requirements
	is_object(req)
}

_specs := [
	{"key": "information_exchange", "req": information_exchange.requirements},
	{"key": "security_awareness_training", "req": security_awareness_training.requirements},
	{"key": "incident_response", "req": incident_response.requirements},
	{"key": "auditing_accountability", "req": auditing_accountability.requirements},
	{"key": "access_control", "req": access_control.requirements},
	{"key": "identification_authentication", "req": identification_authentication.requirements},
	{"key": "configuration_management", "req": configuration_management.requirements},
	{"key": "media_protection", "req": media_protection.requirements},
	{"key": "physical_protection", "req": physical_protection.requirements},
	{"key": "systems_communications_protection", "req": systems_communications_protection.requirements},
	{"key": "formal_audits", "req": formal_audits.requirements},
	{"key": "personnel_security", "req": personnel_security.requirements},
	{"key": "mobile_devices", "req": mobile_devices.requirements},
]

# id -> {area, met}. Requirement ids are unique across areas (distinct prefixes).
_all[id] := {"area": m.area, "met": object.get(_attest(spec.key), id, false) == true} if {
	some spec in _specs
	some id, m in spec.req
}

total_requirements := count(_all)

requirements_met := count([id | some id, c in _all; c.met])

# Per-policy-area rollup, keyed by area name.
policy_areas[name] := {
	"policy_area": r.policy_area,
	"requirements": r.requirements_evaluated,
	"gaps": r.violation_count,
	"compliant": r.compliant,
} if {
	some r in area_reports
	name := r.area_name
}

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"framework": "FBI CJIS Security Policy",
	"reference": "NIST SP 800-53",
	"policy_areas_evaluated": count(area_reports),
	"total_requirements": total_requirements,
	"requirements_met": requirements_met,
	"policy_areas": policy_areas,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"compliant": compliant,
}
