# CIS Microsoft 365 Foundations Benchmark v7.0.0 -- master orchestrator
#
# Aggregates the per-section reports and, just as importantly, states what
# is NOT evaluated. The benchmark defines 160 recommendations across nine
# sections. A caller that reads only `compliant` from a partial assessment
# would draw a false conclusion, so this report deliberately does not
# expose a bare tenant-wide `compliant` boolean. It exposes
# `assessed_controls_compliant` -- true only of the controls actually
# evaluated -- alongside the coverage that qualifies it.
#
# `coverage_accounting` proves the report describes the whole benchmark:
# every recommendation must land in exactly one of four buckets. Until
# 2026-08-25 six landed in none, so the buckets summed to 154 and the
# report silently described a benchmark that does not exist. A count that
# does not add up is the one kind of coverage error a reader can catch
# unaided, so it is published rather than merely asserted in a test.
#
# OPA query path: /v1/data/cis_m365_v7/main/compliance_report

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0 -- master orchestrator"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cis_m365_v7.main

import data.cis_m365_v7.admin_center
import data.cis_m365_v7.attestation
import data.cis_m365_v7.control_index
import data.cis_m365_v7.defender
import data.cis_m365_v7.entra
import data.cis_m365_v7.exchange
import data.cis_m365_v7.fabric
import data.cis_m365_v7.intune
import data.cis_m365_v7.purview
import data.cis_m365_v7.sharepoint
import data.cis_m365_v7.teams
import rego.v1

BENCHMARK_TOTAL_CONTROLS := 160

# Sections with no fact collector at all. Declared explicitly so that a
# reader (or an auditor) sees the gap rather than inferring coverage from
# the absence of violations.
not_evaluated := []

section_reports := [
	admin_center.compliance_report,
	defender.compliance_report,
	purview.compliance_report,
	intune.compliance_report,
	entra.compliance_report,
	exchange.compliance_report,
	sharepoint.compliance_report,
	teams.compliance_report,
	fabric.compliance_report,
]

# array.concat takes exactly two arrays -- fold rather than vararg.
all_violations := array.concat(
	[v | some r in section_reports; some v in r.violations],
	[v | some v in attestation.violation],
)

# The controls a section module implements -- what the library CAN evaluate
# from collected evidence. Static: it does not depend on the input.
evaluated_controls := [c |
	some r in section_reports
	some c in r.controls
]

implemented_control_ids := evaluated_controls

implemented_controls := count(implemented_control_ids)

# The controls actually evaluated for THIS input: a section control whose
# result was decided from collected evidence (pass or fail). A control whose
# evidence is missing was not evaluated, whatever the library implements; on
# empty input this is 0.
evaluated_control_ids := [e.id |
	some e in control_index.CONTROL_INDEX
	e.id in _section_controls
	_raw_status[e.id] in {"pass", "fail"}
]

controls_evaluated := count(evaluated_control_ids)

controls_not_evaluated := BENCHMARK_TOTAL_CONTROLS - controls_evaluated

# The four buckets must partition the benchmark. Anything not implemented
# has to be claimed by a named reason -- an unclaimed control is one the
# report does not mention at all, which reads exactly like a pass. The
# partition is about what the library implements, so it counts
# implemented_controls, not the input-dependent controls_evaluated.
accounted_controls := ((implemented_controls + count(attestation.REQUIRES_ATTESTATION)) + count(attestation.UNRESOLVED)) + count(attestation.NOT_IMPLEMENTED)

default accounting_balanced := false

accounting_balanced if {
	accounted_controls == BENCHMARK_TOTAL_CONTROLS
}

coverage_accounting := {
	"benchmark_total": BENCHMARK_TOTAL_CONTROLS,
	# the implemented controls (kept under its original name)
	"evaluated": implemented_controls,
	"requires_attestation": count(attestation.REQUIRES_ATTESTATION),
	"unresolved": count(attestation.UNRESOLVED),
	"not_implemented": count(attestation.NOT_IMPLEMENTED),
	"accounted": accounted_controls,
	"unaccounted": BENCHMARK_TOTAL_CONTROLS - accounted_controls,
	"balanced": accounting_balanced,
}

default assessed_controls_compliant := false

assessed_controls_compliant if {
	count(all_violations) == 0
}

# ── Per-control results ──────────────────────────────────────────────
# control_results: one object per recommendation of the benchmark (all
# 160, natural id order; CONTROL_INDEX in control_index.rego), each
# {id, status, basis, in_scope, profile, evidence}. No benchmark text.
#
# A control a section evaluates is
#   fail              when a violation of its section cites it and is not
#                     an evidence message;
#   evidence_missing  when its section's gate (`decidable`) says a fact it
#                     reads was not collected, or an evidence message (the
#                     ones ending "(this is not a pass)") cites it;
#   pass              otherwise.
# The gate is what keeps an absent fact from reading as a pass: several
# rules are silent when their fact is missing, so the absence of a
# violation alone is not evidence. A ledger control (attestation module)
# is pass with basis attestation when attested. Unattested, the ones that
# require attestation and the ones whose collectability is unresolved are
# not_attested: all sixteen are recommendations the benchmark marks Manual
# and the module accepts an attestation for, so neither is a pass. A
# not-implemented one (automatable, the collector does not make the call
# yet; none today) is evidence_missing: it is not evaluated at all.
#
# Scope: input.cis_profile.licence ("E3" | "E5") and .level (1 | 2) select
# the recommendations of that licence tier up to that level; the others
# are not_applicable. Absent, the profile is E5 Level 2, which includes
# all 160, so a caller that sends no profile sees every control. Only
# control_results reads the profile: violations and the other fields are
# unchanged by it.

CONTROL_STATUSES := ["pass", "fail", "evidence_missing", "not_attested", "not_applicable"]

_decidable := (((((((admin_center.decidable | defender.decidable) | purview.decidable) | intune.decidable) | entra.decidable) | exchange.decidable) | sharepoint.decidable) | teams.decidable) | fabric.decidable

_control_evidence := object.union_n([
	admin_center.CONTROL_EVIDENCE,
	defender.CONTROL_EVIDENCE,
	purview.CONTROL_EVIDENCE,
	intune.CONTROL_EVIDENCE,
	entra.CONTROL_EVIDENCE,
	exchange.CONTROL_EVIDENCE,
	sharepoint.CONTROL_EVIDENCE,
	teams.CONTROL_EVIDENCE,
	fabric.CONTROL_EVIDENCE,
])

_section_controls := {c | some c in evaluated_controls}

_ledger_ids := (object.keys(attestation.REQUIRES_ATTESTATION) | object.keys(attestation.UNRESOLVED)) | object.keys(attestation.NOT_IMPLEMENTED)

_message_kind(v) := "evidence_missing" if contains(v, "(this is not a pass)")

_message_kind(v) := "fail" if not contains(v, "(this is not a pass)")

# [id, kind] for each section violation; a message may cite several ids
# joined by "/" (the SPF / DKIM / DMARC message cites three)
_cited := {[id, kind] |
	some r in section_reports
	some v in r.violations
	ms := regex.find_all_string_submatch_n(`^CIS ([0-9]+(?:\.[0-9]+)+(?:/[0-9]+(?:\.[0-9]+)+)*): `, v, 1)
	count(ms) == 1
	cited_ids := split(ms[0][1], "/")
	some id in cited_ids
	kind := _message_kind(v)
}

_failed_ids := {pair[0] | some pair in _cited; pair[1] == "fail"}

_unevaluated_ids := {pair[0] | some pair in _cited; pair[1] == "evidence_missing"}

_section_status(id) := "fail" if {
	id in _failed_ids
} else := "evidence_missing" if {
	not id in _decidable
} else := "evidence_missing" if {
	id in _unevaluated_ids
} else := "pass"

_ledger_status(id) := "fail" if {
	id in attestation.failed_ids
} else := "pass" if {
	id in attestation.attested_ids
} else := "not_attested" if {
	not attestation.NOT_IMPLEMENTED[id]
} else := "evidence_missing"

_raw_status[id] := _section_status(id) if some id in _section_controls

_raw_status[id] := _ledger_status(id) if some id in _ledger_ids

_basis(id) := "evidence" if {
	id in _section_controls
} else := "attestation" if {
	not attestation.NOT_IMPLEMENTED[id]
} else := "attestation" if {
	id in attestation.attested_ids
} else := "attestation" if {
	id in attestation.failed_ids
} else := "evidence"

# section controls: the paths their gate reads; ledger controls decided by attestation: the attestation list;
# an unattested not-implemented control has no known path (omitted)
_evidence(id) := _control_evidence[id] if id in _section_controls

_evidence(id) := ["attestations"] if {
	not id in _section_controls
	_basis(id) == "attestation"
}

default _cis_profile := {}

_cis_profile := p if {
	p := input.cis_profile
	is_object(p)
}

default _licence := "E5"

_licence := l if {
	l := _cis_profile.licence
	l in {"E3", "E5"}
}

default _level := 2

_level := l if {
	l := _cis_profile.level
	l in {1, 2}
}

default _profile_defaulted := true

_profile_defaulted := false if {
	_cis_profile.licence in {"E3", "E5"}
	_cis_profile.level in {1, 2}
}

control_results_profile := {
	"licence": _licence,
	"level": _level,
	"defaulted": _profile_defaulted,
	"input": "input.cis_profile {licence: E3|E5, level: 1|2}; default E5 Level 2 (all 160 in scope)",
}

_in_scope(id) if {
	lowest := control_index.CONTROL_SCOPE[id][_licence]
	lowest <= _level
}

# two rules, not an else chain: an in-scope id without a status must drop out (and fail the id test), never
# read as not_applicable
_status(id) := "not_applicable" if not _in_scope(id)

_status(id) := s if {
	_in_scope(id)
	s := _raw_status[id]
}

_with_evidence(base, id) := r if {
	ev := _evidence(id)
	r := object.union(base, {"evidence": ev})
}

_with_evidence(base, id) := base if not _evidence(id)

control_results := [r |
	some e in control_index.CONTROL_INDEX
	s := _status(e.id)
	b := _basis(e.id)
	base := object.union(e, {"status": s, "basis": b, "in_scope": s != "not_applicable"})
	r := _with_evidence(base, e.id)
]

_control_result_statuses := [r.status | some r in control_results]

# total_controls: the recommendations in scope for input.cis_profile (160 with
# no profile). failed_controls: those of them that are fail, evidence_missing
# or not_attested -- everything in scope that is not a pass. On empty input
# failed_controls == total_controls.
FAILING_STATUSES := {"fail", "evidence_missing", "not_attested"}

total_controls := count([r | some r in control_results; r.in_scope])

failed_controls := count([r | some r in control_results; r.in_scope; r.status in FAILING_STATUSES])

control_result_counts := {s: n |
	some s in CONTROL_STATUSES
	n := count([x | some x in _control_result_statuses; x == s])
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"benchmark_released": "2026-05-20",
	"benchmark_total_controls": BENCHMARK_TOTAL_CONTROLS,
	"total_controls": total_controls,
	"failed_controls": failed_controls,
	# what was evaluated for this input (decided pass or fail from evidence)
	"controls_evaluated": controls_evaluated,
	"controls_not_evaluated": controls_not_evaluated,
	"coverage_percentage": round((controls_evaluated * 100) / BENCHMARK_TOTAL_CONTROLS),
	"evaluated_control_ids": evaluated_control_ids,
	# what the library implements, whatever the input
	"implemented_controls": implemented_controls,
	"implemented_control_ids": implemented_control_ids,
	"coverage_accounting": coverage_accounting,
	"sections_evaluated": section_reports,
	"sections_not_evaluated": not_evaluated,
	# Controls with no collector path are reported, never omitted -- an
	# omitted control is indistinguishable from a passing one.
	"no_collector_path": attestation.compliance_report,
	"violations": all_violations,
	"violation_count": count(all_violations),
	# Scoped deliberately: true means "no violation among the controls that
	# were evaluated", NOT "the tenant meets the benchmark".
	"assessed_controls_compliant": assessed_controls_compliant,
	"interpretation": "This is a partial assessment. assessed_controls_compliant covers only evaluated_control_ids and must not be read as benchmark compliance.",
	# one result per recommendation (all 160): see the block above
	"control_results": control_results,
	"control_result_counts": control_result_counts,
	"control_results_profile": control_results_profile,
}
