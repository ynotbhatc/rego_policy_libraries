# IRS Publication 1075 (Rev. 11-2021) — master orchestrator
#
# Aggregates the eight Pub 1075 safeguard areas — the six IRC 6103(p)(4)
# safeguard requirements (A) Recordkeeping through (F) Disposal, plus
# Computer System Security (§9, NIST SP 800-53 Rev 5 tailoring) and Data
# Incident Response (§10) — into one compliance report with a per-area
# rollup. Pub 1075 has no maturity tiers — straight fail-closed requirement
# pass/fail. Fail-closed: an unattested requirement is a gap.
#
# Entry point: data.irs_1075.main.compliance_report

package irs_1075.main

import rego.v1

import data.irs_1075.computer_security
import data.irs_1075.disposal
import data.irs_1075.incident_response
import data.irs_1075.other_safeguards
import data.irs_1075.recordkeeping
import data.irs_1075.reporting
import data.irs_1075.restricting_access
import data.irs_1075.secure_storage

# Per-area reports, in Pub 1075 section order.
area_reports := [
	recordkeeping.compliance_report,
	secure_storage.compliance_report,
	restricting_access.compliance_report,
	other_safeguards.compliance_report,
	reporting.compliance_report,
	disposal.compliance_report,
	computer_security.compliance_report,
	incident_response.compliance_report,
]

all_violations := [v | some r in area_reports; some v in r.violations]

# Attestation object for an area, defaulted to {} so the report is robust
# to entirely-absent input (the standard bare `opa eval` verify command) and
# to a malformed non-object `requirements` value, which would otherwise make
# object.get undefined and silently drop the area's ids from _all.
default _attest(_) := {}

_attest(area) := req if {
	req := input.irs_1075[area].requirements
	is_object(req)
}

_specs := [
	{"key": "recordkeeping", "req": recordkeeping.requirements},
	{"key": "secure_storage", "req": secure_storage.requirements},
	{"key": "restricting_access", "req": restricting_access.requirements},
	{"key": "other_safeguards", "req": other_safeguards.requirements},
	{"key": "reporting", "req": reporting.requirements},
	{"key": "disposal", "req": disposal.requirements},
	{"key": "computer_security", "req": computer_security.requirements},
	{"key": "incident_response", "req": incident_response.requirements},
]

# id -> {section, met}. Requirement ids are unique across areas (distinct prefixes).
_all[id] := {"section": m.section, "met": object.get(_attest(spec.key), id, false) == true} if {
	some spec in _specs
	some id, m in spec.req
}

total_requirements := count(_all)

requirements_met := count([id | some id, c in _all; c.met])

# Per-area rollup, keyed by area name.
safeguard_areas[name] := {
	"section": r.section,
	"authority": r.authority,
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
	"framework": "IRS Publication 1075 (Rev. 11-2021)",
	"reference": "IRC 6103(p)(4); NIST SP 800-53 Rev 5",
	"areas_evaluated": count(area_reports),
	"total_requirements": total_requirements,
	"requirements_met": requirements_met,
	"safeguard_areas": safeguard_areas,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"compliant": compliant,
}
