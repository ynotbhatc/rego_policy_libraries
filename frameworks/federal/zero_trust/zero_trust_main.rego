# CISA Zero Trust Maturity Model v2.0 — master orchestrator
#
# Aggregates the five pillars (Identity, Devices, Networks, Applications &
# Workloads, Data) and the three cross-cutting capabilities (Visibility &
# Analytics, Automation & Orchestration, Governance) into one Zero Trust
# posture report, with per-pillar rollup and per-maturity-stage coverage.
# Informed by NIST SP 800-207. Fail-closed: an unattested criterion is a gap.
#
# Entry point: data.zero_trust.main.compliance_report

package zero_trust.main

import rego.v1

import data.zero_trust.applications_workloads
import data.zero_trust.automation_orchestration
import data.zero_trust.data
import data.zero_trust.devices
import data.zero_trust.governance
import data.zero_trust.identity
import data.zero_trust.networks
import data.zero_trust.visibility_analytics

# Per-pillar / per-capability reports.
pillar_reports := [
	identity.compliance_report,
	devices.compliance_report,
	networks.compliance_report,
	applications_workloads.compliance_report,
	data.compliance_report,
	visibility_analytics.compliance_report,
	automation_orchestration.compliance_report,
	governance.compliance_report,
]

# All gaps, flattened from every pillar's report.
all_violations := [v | some r in pillar_reports; some v in r.violations]

# Attestation object for a pillar, defaulting to {} so the report is robust to
# entirely-absent input (the standard bare `opa eval` verify command).
default _attest(_) := {}

_attest(pillar) := req if {
	req := input.zero_trust[pillar].criteria
	is_object(req)
}

# Each pillar's criteria paired with its attestation key, so the master can
# compute per-maturity-stage coverage across the whole model.
_specs := [
	{"key": "identity", "criteria": identity.criteria},
	{"key": "devices", "criteria": devices.criteria},
	{"key": "networks", "criteria": networks.criteria},
	{"key": "applications_workloads", "criteria": applications_workloads.criteria},
	{"key": "data", "criteria": data.criteria},
	{"key": "visibility_analytics", "criteria": visibility_analytics.criteria},
	{"key": "automation_orchestration", "criteria": automation_orchestration.criteria},
	{"key": "governance", "criteria": governance.criteria},
]

# id -> {stage, met}. Criteria ids are unique across pillars (distinct prefixes).
_all[id] := {"stage": m.stage, "met": object.get(_attest(spec.key), id, false) == true} if {
	some spec in _specs
	some id, m in spec.criteria
}

total_criteria := count(_all)

criteria_met := count([id | some id, c in _all; c.met])

# Coverage per maturity stage present in the model.
maturity_by_stage[stage] := {"total": total, "met": met} if {
	some stage in {c.stage | some _, c in _all}
	total := count([id | some id, c in _all; c.stage == stage])
	met := count([id | some id, c in _all; c.stage == stage; c.met])
}

# Per-pillar rollup, keyed by pillar name.
pillars[name] := {"criteria": r.criteria_evaluated, "gaps": r.violation_count, "compliant": r.compliant} if {
	some r in pillar_reports
	name := r.pillar
}

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"framework": "CISA Zero Trust Maturity Model v2.0",
	"reference": "NIST SP 800-207",
	"pillars_evaluated": count(pillar_reports),
	"total_criteria": total_criteria,
	"criteria_met": criteria_met,
	"maturity_by_stage": maturity_by_stage,
	"pillars": pillars,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"compliant": compliant,
}
