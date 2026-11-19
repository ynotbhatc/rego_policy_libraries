# METADATA
# title: "NIST SP 800-53 Rev 5 — catalog check: all 20 families, every Low and Moderate baseline control, 370 ids"
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
# Coverage (checked against the NIST OSCAL catalog, SP 800-53 Rev 5 release 5.2.0, which is also the
# catalog behind this repo's converters/exports/oscal profiles, commit 78650f02): the catalog has 20
# families and 1,014 controls and enhancements that are not withdrawn (300 base controls). This module
# evaluates 370 of them: 255 of the 300 base controls, in all 20 families, and 115 enhancements, which is every
# control the NIST SP 800-53B Low and Moderate baselines select (149 and 287). The 45 base controls still missing
# are in SC (27), SI (10), AU (3), IA (3) and CM (2); the High baseline's further enhancements are not evaluated yet.
# A base control never fails on an enhancement's requirement. Organizational controls with no machine-checkable
# evidence require a signed attestation ({attested: true, by, date}). A compliant result means "no finding in the
# 370 evaluated ids", nothing more. control_results gives every id's outcome, and baseline_results says, for each
# 800-53B and FedRAMP baseline, which of its controls are evaluated and how they came out and which are not
# evaluated; that is a statement about this module, not a baseline authorization. Withdrawn controls are not assessed.
#
# Report contract: total_controls is the number of ids evaluated; failed_controls is the number of
# distinct ids with a finding (each evaluated id produces at most one finding), so failed <= total.
#
# Families aggregated: all 20 Rev 5 families (AC AT AU CA CM CP IA IR MA MP PE PL PM PS PT RA SA SC SI SR).

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

violations := all_violations

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
# baseline keys (see baseline_results) that select the id.
# Findings grouped by the id(s) their prefix names, parsed once per finding.
_findings_by_id[id] contains v if {
	some v in violations
	some id in _finding_ids(v)
}

_findings_for[id] := sort(object.get(_findings_by_id, id, set())) if some id in evaluated_controls

_baseline_sets[k] := {id | some id in ids} if some k, ids in index.baselines

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

control_results := [{
	"id": id,
	"status": _status_of[id],
	"basis": _basis(id),
	"baselines": [k | some k, members in _baseline_sets; id in members],
	"findings": _findings_for[id],
} |
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

compliance_report := {
	"framework": "NIST SP 800-53 Rev 5",
	"version": "Rev 5",
	"regulation": "NIST SP 800-53 Rev 5 control catalog — all 20 families; 370 of 1,014 active controls and enhancements (255 of 300 base controls; all of 800-53B Low and Moderate); per-baseline results, not a baseline authorization",
	"assessed_at": assessed_at,
	"total_controls": total_controls,
	"failed_controls": failed_controls,
	"failed_control_ids": sort(failed_control_ids),
	"coverage": {
		"catalog": "NIST SP 800-53 Rev 5, OSCAL release 5.2.0",
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
		"AC": {"violations": count(ac_v), "compliant": count(ac_v) == 0},
		"AT": {"violations": count(at_v), "compliant": count(at_v) == 0},
		"AU": {"violations": count(au_v), "compliant": count(au_v) == 0},
		"CA": {"violations": count(ca_v), "compliant": count(ca_v) == 0},
		"CM": {"violations": count(cm_v), "compliant": count(cm_v) == 0},
		"CP": {"violations": count(cp_v), "compliant": count(cp_v) == 0},
		"IA": {"violations": count(ia_v), "compliant": count(ia_v) == 0},
		"IR": {"violations": count(ir_v), "compliant": count(ir_v) == 0},
		"MA": {"violations": count(ma_v), "compliant": count(ma_v) == 0},
		"MP": {"violations": count(mp_v), "compliant": count(mp_v) == 0},
		"PE": {"violations": count(pe_v), "compliant": count(pe_v) == 0},
		"PL": {"violations": count(pl_v), "compliant": count(pl_v) == 0},
		"PM": {"violations": count(pm_v), "compliant": count(pm_v) == 0},
		"PS": {"violations": count(ps_v), "compliant": count(ps_v) == 0},
		"PT": {"violations": count(pt_v), "compliant": count(pt_v) == 0},
		"RA": {"violations": count(ra_v), "compliant": count(ra_v) == 0},
		"SA": {"violations": count(sa_v), "compliant": count(sa_v) == 0},
		"SC": {"violations": count(sc_v), "compliant": count(sc_v) == 0},
		"SI": {"violations": count(si_v), "compliant": count(si_v) == 0},
		"SR": {"violations": count(sr_v), "compliant": count(sr_v) == 0},
	},
}
