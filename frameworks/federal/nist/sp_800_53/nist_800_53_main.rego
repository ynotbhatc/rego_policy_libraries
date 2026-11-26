# METADATA
# title: "NIST SP 800-53 Rev 5 — catalog check: all 300 base controls, every Low/Moderate/High and Privacy baseline control, the Release 5.2.0 additions, AC-17(9) and SA-10(1), 546 ids"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_53.main

import rego.v1

# NIST SP 800-53 Rev 5 — Master orchestrator.
#
# Aggregates violations from the per-family modules under
# data.nist.sp800_53.* and exports the compliance_report shape
# expected by ansible/playbooks/generic_framework_assessment.yml.
#
# OPA endpoint: POST <opa_security>/v1/data/nist_800_53/main/compliance_report
#
# Coverage (checked against the NIST OSCAL catalog, SP 800-53 Rev 5 release 5.2.0 of 27 August 2025, at
# usnistgov/oscal-content v1.6.0, commit f0de6d8d; the repo's converters/exports/oscal profiles are built from
# v1.5.0, commit 78650f02, which has the same ids and baselines): the catalog has 20
# families and 1,014 controls and enhancements that are not withdrawn (300 base controls). This module
# evaluates 546 of them: all 300 base controls, in all 20 families, and 246 enhancements, which is every control
# the NIST SP 800-53B Low (149), Moderate (287) and High (370) baselines and the FedRAMP Rev 5 Low (156), Moderate
# (323) and High (410) baselines select, all 96 ids of the Privacy baseline, and the two enhancements Release
# 5.2.0 added, SA-15(13) and SI-2(7), and the two enhancements AC-17(9) and SA-10(1), which TX-RAMP Level 2 selects,
# all four in no NIST or FedRAMP baseline (the release's new base control, SA-24, is one of
# the 300). The 468 other enhancements (in none of those baselines) are not evaluated; SI-7(12), whose requirement
# Release 5.2.0 widened from user-installed software to all organization-defined software, is one of them.
# A base control never fails on an enhancement's requirement. Organizational controls with no machine-checkable
# evidence require a signed attestation ({attested: true, by, date}). A compliant result means "no finding in the
# 546 evaluated ids", nothing more. control_results gives every id's outcome, and baseline_results says, for each
# 800-53B and FedRAMP baseline, which of its controls are evaluated and how they came out and which are not
# evaluated; that is a statement about this module, not a baseline authorization. Withdrawn controls are not assessed.
#
# Report contract: total_controls is the number of ids evaluated; failed_controls is the number of
# distinct ids with a finding, so failed <= total. Without benchmark results each evaluated id produces at
# most one finding; a benchmark gap adds a second finding to an id that already has one.
#
# Benchmark results (optional): the same input may carry STIG results in the two shapes
# data.crosswalk.correlation reads, and no other:
#   input.reports  : [ <STIG compliance_report with rule_results and facts_supplied>, ... ]
#   input.findings : [ {"stig_id": "RHEL-09-255010", "status": "Not_a_Finding" | "Open" | ...}, ... ]
# The crosswalk spine (crosswalk/correlation.rego with crosswalk/stig_800_53/data.json, DISA's rule -> CCI ->
# 800-53 map) turns them into one technical verdict per 800-53 base control, and this report carries it:
#   - gap (a mapped rule is Open): the control fails, whatever its declared evidence or attestation says. The
#     finding names the Open rules.
#   - satisfied, not_reviewed, not_applicable: recorded on the control's row under "benchmark" with the
#     contributing rule ids. The row's status does not change: a satisfied benchmark verdict covers the
#     technical part on the assessed platform only, so the control's own evidence and attestation still decide
#     whether it passes. Benchmark results never turn a control into a pass.
#   - no mapped rule supplied: benchmark.status is "not_evaluated".
# The map is at base-control granularity, so enhancement rows are always "not_evaluated". Fail closed: a report
# with facts_supplied == false counts every one of its rules as Open; a rule id the crosswalk does not know
# speaks to no control and is listed under benchmark_evidence.unmapped_rules; benchmark results that cannot be
# read, or that arrive when the crosswalk is not loaded next to this module, are FAIL-CLOSED findings.
# With neither key in the input the report is the same as before: no "benchmark" on the rows, no
# "benchmark_evidence" block. Nothing here scores, weights or ranks; verdicts are carried through the map.
#
# Families aggregated: all 20 Rev 5 families (AC AT AU CA CM CP IA IR MA MP PE PL PM PS PT RA SA SC SI SR).

import data.crosswalk.correlation as spine
import data.nist.sp800_53.access_control as ac
import data.nist.sp800_53.assessment_authorization as ca
import data.nist.sp800_53.audit_accountability as au
import data.nist.sp800_53.awareness_training as at
import data.nist.sp800_53.configuration_management as cm
import data.nist.sp800_53.contingency_planning as cp
import data.nist.sp800_53.identification_authentication as ia
import data.nist.sp800_53.incident_response as ir
import data.nist.sp800_53.index
import data.nist.sp800_53.maintenance as ma
import data.nist.sp800_53.media_protection as mp
import data.nist.sp800_53.personnel_security as ps
import data.nist.sp800_53.physical_environmental as pe
import data.nist.sp800_53.pii_processing_transparency as pt
import data.nist.sp800_53.planning as pl
import data.nist.sp800_53.program_management as pm
import data.nist.sp800_53.risk_assessment as ra
import data.nist.sp800_53.supply_chain_risk as sr
import data.nist.sp800_53.system_communications as sc
import data.nist.sp800_53.system_information_integrity as si
import data.nist.sp800_53.system_services_acquisition as sa

default compliant := false

ac_v := [v | some v in ac.violation]
at_v := [v | some v in at.violation]
au_v := [v | some v in au.violation]
ca_v := [v | some v in ca.violation]
cm_v := [v | some v in cm.violation]
cp_v := [v | some v in cp.violation]
ia_v := [v | some v in ia.violation]
ir_v := [v | some v in ir.violation]
ma_v := [v | some v in ma.violation]
mp_v := [v | some v in mp.violation]
pe_v := [v | some v in pe.violation]
pl_v := [v | some v in pl.violation]
pm_v := [v | some v in pm.violation]
ps_v := [v | some v in ps.violation]
pt_v := [v | some v in pt.violation]
ra_v := [v | some v in ra.violation]
sa_v := [v | some v in sa.violation]
sc_v := [v | some v in sc.violation]
si_v := [v | some v in si.violation]
sr_v := [v | some v in sr.violation]

all_violations := [v | some fam in [ac_v, at_v, au_v, ca_v, cm_v, cp_v, ia_v, ir_v, ma_v, mp_v, pe_v, pl_v, pm_v, ps_v, pt_v, ra_v, sa_v, sc_v, si_v, sr_v]; some v in fam]

violations := array.concat(all_violations, _bench_violations)

# --- Benchmark results through the crosswalk spine ---------------------------------------------------------
default _bench_supplied := false

_bench_supplied if _ = input.reports

_bench_supplied if _ = input.findings

# The spine is a separate package with its own data file; when either is absent every reference below is
# undefined, which must read as "could not be evaluated", never as "no gap".
default _spine_loaded := false

_spine_loaded if {
	spine.spine_loaded == true
	is_number(spine.summary.rules_supplied)
}

# Technical verdict per 800-53 control, straight from the spine; empty unless benchmark results were supplied
# and the spine is loaded.
_bench[id] := ev if {
	_bench_supplied
	_spine_loaded
	some id, ev in spine.control_evidence
}

_bench_ids_with(st) := [id | some id in index.order; _bench[id].status == st]

# Spine controls this module does not evaluate (none with the shipped map; kept visible if the map grows).
_bench_outside := sort([id | some id, _ in _bench; not id in evaluated_controls])

_bench_gap_ids := array.concat(_bench_ids_with("gap"), [id | some id in _bench_outside; _bench[id].status == "gap"])

_bench_rule_list(rules) := concat(", ", rules) if {
	count(rules) <= 5
} else := sprintf("%s and %d more, listed on the control's row", [concat(", ", array.slice(rules, 0, 5)), count(rules) - 5])

_bench_gap_violations := [msg |
	some id in _bench_gap_ids
	rules := _bench[id].open_rules
	msg := sprintf("NIST %s: benchmark results show a gap: %d mapped STIG rule(s) Open (%s); the control fails regardless of its declared evidence or attestation", [id, count(rules), _bench_rule_list(rules)])
]

_bench_fail_closed contains "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but the crosswalk spine (crosswalk/correlation.rego and crosswalk/stig_800_53/data.json) is not loaded, so no technical verdict could be taken; this is not a passing result" if {
	_bench_supplied
	not _spine_loaded
}

_bench_fail_closed contains "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but no rule row could be read from them; this is not a passing result" if {
	_bench_supplied
	_spine_loaded
	spine.summary.rules_supplied == 0
}

_bench_fail_closed contains msg if {
	_bench_supplied
	_spine_loaded
	n := spine.summary.rules_supplied
	is_number(n)
	n > 0
	count(_bench) == 0
	msg := sprintf("FAIL-CLOSED: none of the %d benchmark rule id(s) supplied is in the crosswalk, so no technical verdict could be taken; this is not a passing result", [n])
}

_bench_fail_closed contains msg if {
	_bench_supplied
	_spine_loaded
	n := spine.reports_without_facts
	is_number(n)
	n > 0
	msg := sprintf("FAIL-CLOSED: %d benchmark report(s) had no facts supplied (facts_supplied is false); every rule in them counts as Open", [n])
}

_bench_violations := array.concat(_bench_gap_violations, sort(_bench_fail_closed))

_bench_not_evaluated := {"status": "not_evaluated", "rules": [], "open_rules": [], "not_reviewed_rules": []}

_bench_row(id) := _bench[id] if {
	_bench[id]
} else := _bench_not_evaluated

_with_bench(id, row) := object.union(row, {"benchmark": _bench_row(id)}) if {
	_bench_supplied
} else := row

_bench_rule := "A benchmark gap fails the control regardless of its declared evidence or attestation. A satisfied benchmark verdict is recorded on the row and does not change its status: the control's own evidence and attestation still apply. Benchmark results never turn a control into a pass."

# The benchmark_evidence block of the report; undefined when no benchmark results were supplied. The spine's
# values are bound in the body, so anything it cannot give falls through to the short block and the report
# stays defined.
_bench_block := {
	"supplied": true,
	"spine_loaded": true,
	"source": "crosswalk.correlation: STIG rule id -> CCI -> NIST SP 800-53 (DISA), base-control granularity",
	"combination_rule": _bench_rule,
	"rules_supplied": summary.rules_supplied,
	"rules_unmapped": summary.rules_unmapped,
	"unmapped_rules": unmapped,
	"reports_without_facts": without_facts,
	"satisfied": _bench_ids_with("satisfied"),
	"gap": _bench_ids_with("gap"),
	"not_reviewed": _bench_ids_with("not_reviewed"),
	"not_applicable": _bench_ids_with("not_applicable"),
	"controls_not_in_module": _bench_outside,
} if {
	_bench_supplied
	_spine_loaded
	summary := spine.summary
	is_number(summary.rules_supplied)
	is_number(summary.rules_unmapped)
	unmapped := sort(spine.unmapped_rules)
	without_facts := spine.reports_without_facts
} else := {
	"supplied": true,
	"spine_loaded": false,
	"combination_rule": _bench_rule,
} if {
	_bench_supplied
}

# What the report gains: nothing without benchmark results, so the report is then what it has always been.
_bench_addition := object.union({}, {}) if not _bench_supplied

_bench_addition := object.union({}, {"benchmark_evidence": _bench_block}) if _bench_supplied

# Family summary row: the family's own findings plus the benchmark gaps on its controls.
_fam_summary(fam, v) := {"violations": n, "compliant": n == 0} if {
	n := count(v) + count([id | some id in _bench_gap_ids; startswith(id, concat("", [fam, "-"]))])
}

# Controls and enhancements evaluated across all 20 families; tests/test_nist_800_53_main.rego asserts it
# equals the union of the families' evaluated_controls.
total_controls := count(evaluated_controls)

evaluated_controls := {id | some fam in [ac.evaluated_controls, at.evaluated_controls, au.evaluated_controls, ca.evaluated_controls, cm.evaluated_controls, cp.evaluated_controls, ia.evaluated_controls, ir.evaluated_controls, ma.evaluated_controls, mp.evaluated_controls, pe.evaluated_controls, pl.evaluated_controls, pm.evaluated_controls, ps.evaluated_controls, pt.evaluated_controls, ra.evaluated_controls, sa.evaluated_controls, sc.evaluated_controls, si.evaluated_controls, sr.evaluated_controls]; some id in fam}

# Control ids named by a finding: the "NIST <FAM>-<n>[/<n>][(<e>)]:" prefix every family message carries.
_finding_ids(msg) := {id |
	some m in regex.find_all_string_submatch_n(`^NIST ([A-Z]{2})-([0-9]+(?:/[0-9]+)*)(\([0-9]+\))?:`, msg, 1)
	some n in split(m[2], "/")
	id := concat("", [m[1], "-", n, m[3]])
}

failed_control_ids := {id |
	some v in violations
	some id in _finding_ids(v)
}

failed_controls := count(failed_control_ids & evaluated_controls)

compliant if count(violations) == 0

# Per-control results: one row per evaluated id, passes included, in natural id order.
#   pass              no finding for the id (every family check is fail-closed: no evidence is a finding)
#   fail              a finding that is not about missing evidence or a missing attestation
#   evidence_missing  the facts the check reads were not collected
#   not_attested      an organizational control without its signed attestation
# basis is "attestation" for the ids in index.attestation_controls, otherwise "evidence"; baselines lists the
# baseline keys (see baseline_results) that select the id. When benchmark results are supplied each row also
# carries benchmark: {status, rules, open_rules, not_reviewed_rules} (see the header).
# Findings grouped by the id(s) their prefix names, parsed once per finding.
_findings_by_id[id] contains v if {
	some v in violations
	some id in _finding_ids(v)
}

# object.get reads each grouped rule once as a whole object (a keyed lookup re-evaluates the rule per id).
_findings_for[id] := sort(object.get(_findings_by_id, id, set())) if some id in evaluated_controls

# Baseline keys that select each id, built once.
_baselines_of[id] contains k if {
	some k, ids in index.baselines
	some id in ids
}

_baselines_for(id) := sort(object.get(_baselines_of, id, set()))

_finding_status(msg) := "not_attested" if {
	contains(msg, "not attested")
} else := "evidence_missing" if {
	contains(msg, "evidence missing")
} else := "fail"

_status(msgs) := "pass" if {
	count(msgs) == 0
} else := "fail" if {
	"fail" in {_finding_status(m) | some m in msgs}
} else := "not_attested" if {
	"not_attested" in {_finding_status(m) | some m in msgs}
} else := "evidence_missing"

_basis(id) := "attestation" if {
	id in index.attestation_controls
} else := "evidence"

_status_of[id] := _status(_findings_for[id]) if some id in evaluated_controls

control_results := [_with_bench(id, {
	"id": id,
	"status": _status_of[id],
	"basis": _basis(id),
	"baselines": _baselines_for(id),
	"findings": _findings_for[id],
}) |
	some id in index.order
]

control_result_counts := {s: count([id | some id, st in _status_of; st == s]) | some s in ["pass", "fail", "evidence_missing", "not_attested"]}

# Per-baseline results: for each imported baseline, how many of its controls this module evaluates and how they
# came out, and which it does not evaluate (natural order). This is a statement about this module's ids, not a
# baseline authorization: not_evaluated controls are unassessed, never assumed met.
baseline_results[k] := {
	"title": index.baseline_titles[k],
	"in_scope": count(ids),
	"evaluated": count(ev),
	"passed": count([id | some id in ev; _status_of[id] == "pass"]),
	"not_passed": count([id | some id in ev; _status_of[id] != "pass"]),
	"not_passed_ids": [id | some id in ev; _status_of[id] != "pass"],
	"not_evaluated": count(ids) - count(ev),
	"not_evaluated_ids": [id | some id in ids; not id in evaluated_controls],
} if {
	some k, ids in index.baselines
	ev := [id | some id in ids; id in evaluated_controls]
}

# Default for fields supplied via input. Without a default, an undefined
# reference inside the object literal would make the whole report undefined
# (and the OPA endpoint would return {}).
default assessed_at := "unknown"

assessed_at := input.assessment_date

compliance_report := object.union(
	{
		"framework": "NIST SP 800-53 Rev 5",
		"version": "Rev 5",
		"release": "5.2.0",
		"regulation": "NIST SP 800-53 Rev 5 control catalog — all 20 families; 546 of 1,014 active controls and enhancements of Release 5.2.0 (all 300 base controls; every 800-53B Low, Moderate, High and Privacy control and every FedRAMP Low, Moderate and High control; the Release 5.2.0 enhancements SA-15(13) and SI-2(7); AC-17(9) and SA-10(1), which TX-RAMP Level 2 selects); per-baseline results, not a baseline authorization",
		"assessed_at": assessed_at,
		"total_controls": total_controls,
		"failed_controls": failed_controls,
		"failed_control_ids": sort(failed_control_ids),
		"coverage": {
			"catalog": "NIST SP 800-53 Rev 5, OSCAL release 5.2.0",
			"catalog_release_date": "2025-08-27",
			"release_5_2_0_additions_evaluated": [id | some id in ["SA-15(13)", "SA-24", "SI-2(7)"]; id in evaluated_controls],
			"catalog_families": 20,
			"catalog_active_controls_and_enhancements": 1014,
			"catalog_active_base_controls": 300,
			"families_evaluated": ["AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR"],
			"controls_evaluated": total_controls,
			"base_controls_evaluated": count({id | some id in evaluated_controls; not contains(id, "(")}),
			"enhancements_evaluated": count({id | some id in evaluated_controls; contains(id, "(")}),
			"withdrawn_not_assessed": ["AC-15", "SC-19"],
			"baseline_assessment": false,
		},
		"control_results": control_results,
		"control_result_counts": control_result_counts,
		"baseline_results": baseline_results,
		"violations": violations,
		"violation_count": count(violations),
		"compliant": compliant,
		"families_evaluated": {
			"AC": ac.compliance_report.family,
			"AT": at.compliance_report.family,
			"AU": au.compliance_report.family,
			"CA": ca.compliance_report.family,
			"CM": cm.compliance_report.family,
			"CP": cp.compliance_report.family,
			"IA": ia.compliance_report.family,
			"IR": ir.compliance_report.family,
			"MA": ma.compliance_report.family,
			"MP": mp.compliance_report.family,
			"PE": pe.compliance_report.family,
			"PL": pl.compliance_report.family,
			"PM": pm.compliance_report.family,
			"PS": ps.compliance_report.family,
			"PT": pt.compliance_report.family,
			"RA": ra.compliance_report.family,
			"SA": sa.compliance_report.family,
			"SC": sc.compliance_report.family,
			"SI": si.compliance_report.family,
			"SR": sr.compliance_report.family,
		},
		"family_summary": {
			"AC": _fam_summary("AC", ac_v),
			"AT": _fam_summary("AT", at_v),
			"AU": _fam_summary("AU", au_v),
			"CA": _fam_summary("CA", ca_v),
			"CM": _fam_summary("CM", cm_v),
			"CP": _fam_summary("CP", cp_v),
			"IA": _fam_summary("IA", ia_v),
			"IR": _fam_summary("IR", ir_v),
			"MA": _fam_summary("MA", ma_v),
			"MP": _fam_summary("MP", mp_v),
			"PE": _fam_summary("PE", pe_v),
			"PL": _fam_summary("PL", pl_v),
			"PM": _fam_summary("PM", pm_v),
			"PS": _fam_summary("PS", ps_v),
			"PT": _fam_summary("PT", pt_v),
			"RA": _fam_summary("RA", ra_v),
			"SA": _fam_summary("SA", sa_v),
			"SC": _fam_summary("SC", sc_v),
			"SI": _fam_summary("SI", si_v),
			"SR": _fam_summary("SR", sr_v),
		},
	},
	_bench_addition,
)
