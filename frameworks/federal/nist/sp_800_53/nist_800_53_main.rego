# METADATA
# title: "NIST SP 800-53 Rev 5 — partial catalog check: 109 controls and enhancements in 7 of 20 families"
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
# evaluates 109 of them — 92 base controls and 17 enhancements (AC-2(1), AC-4(1), AC-6(1), AC-6(2), AC-9(1),
# AC-9(4), AC-11(1), AC-12(1), AC-17(1), AC-17(2), AC-18(1), IA-2(1), IA-2(2), IA-5(1), SC-8(1), SC-28(1),
# SC-45(1)) — in 7 families. A base control never fails on an enhancement's requirement. It is not a Low / Moderate / High baseline assessment; a compliant result
# means "no finding in the 109 evaluated ids", nothing more. Withdrawn controls (AC-15, SC-19) are not
# assessed.
#
# Report contract: total_controls is the number of ids evaluated; failed_controls is the number of
# distinct ids with a finding (each evaluated id produces at most one finding), so failed <= total.
#
# Families currently aggregated (others may be added incrementally):
#   AC — Access Control
#   AU — Audit and Accountability
#   CM — Configuration Management
#   IA — Identification and Authentication
#   IR — Incident Response
#   SC — System and Communications Protection
#   SI — System and Information Integrity

import data.nist.sp800_53.access_control as ac
import data.nist.sp800_53.audit_accountability as au
import data.nist.sp800_53.configuration_management as cm
import data.nist.sp800_53.identification_authentication as ia
import data.nist.sp800_53.incident_response as ir
import data.nist.sp800_53.system_communications as sc
import data.nist.sp800_53.system_information_integrity as si

default compliant := false

ac_v := [v | some v in ac.violation]
au_v := [v | some v in au.violation]
cm_v := [v | some v in cm.violation]
ia_v := [v | some v in ia.violation]
ir_v := [v | some v in ir.violation]
sc_v := [v | some v in sc.violation]
si_v := [v | some v in si.violation]

# Nested 2-arg array.concat per repo convention
_ac_au := array.concat(ac_v, au_v)
_ac_au_cm := array.concat(_ac_au, cm_v)
_acm_ia := array.concat(_ac_au_cm, ia_v)
_acm_ia_ir := array.concat(_acm_ia, ir_v)
_acm_ia_ir_sc := array.concat(_acm_ia_ir, sc_v)
all_violations := array.concat(_acm_ia_ir_sc, si_v)

violations := all_violations

# Controls and enhancements evaluated across all aggregated families. Update when new families are wired
# in; tests/test_nist_800_53_main.rego asserts it equals the union of the families' evaluated_controls.
total_controls := 109 # AC(34) + AU(12) + CM(11) + IA(11) + IR(9) + SC(20) + SI(12)

evaluated_controls := (((((ac.evaluated_controls | au.evaluated_controls) | cm.evaluated_controls) | ia.evaluated_controls) | ir.evaluated_controls) | sc.evaluated_controls) | si.evaluated_controls

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

# Default for fields supplied via input. Without a default, an undefined
# reference inside the object literal would make the whole report undefined
# (and the OPA endpoint would return {}).
default assessed_at := "unknown"

assessed_at := input.assessment_date

compliance_report := {
	"framework": "NIST SP 800-53 Rev 5",
	"version": "Rev 5",
	"regulation": "NIST SP 800-53 Rev 5 control catalog — partial: 109 of 1,014 active controls and enhancements, 7 of 20 families; not a baseline assessment",
	"assessed_at": assessed_at,
	"total_controls": total_controls,
	"failed_controls": failed_controls,
	"failed_control_ids": sort(failed_control_ids),
	"coverage": {
		"catalog": "NIST SP 800-53 Rev 5, OSCAL release 5.2.0",
		"catalog_families": 20,
		"catalog_active_controls_and_enhancements": 1014,
		"catalog_active_base_controls": 300,
		"families_evaluated": ["AC", "AU", "CM", "IA", "IR", "SC", "SI"],
		"controls_evaluated": total_controls,
		"base_controls_evaluated": 92,
		"enhancements_evaluated": 17,
		"withdrawn_not_assessed": ["AC-15", "SC-19"],
		"baseline_assessment": false,
	},
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
	"families_evaluated": {
		"AC": ac.compliance_report.family,
		"AU": au.compliance_report.family,
		"CM": cm.compliance_report.family,
		"IA": ia.compliance_report.family,
		"IR": ir.compliance_report.family,
		"SC": sc.compliance_report.family,
		"SI": si.compliance_report.family,
	},
	"family_summary": {
		"AC": {"violations": count(ac_v), "compliant": count(ac_v) == 0},
		"AU": {"violations": count(au_v), "compliant": count(au_v) == 0},
		"CM": {"violations": count(cm_v), "compliant": count(cm_v) == 0},
		"IA": {"violations": count(ia_v), "compliant": count(ia_v) == 0},
		"IR": {"violations": count(ir_v), "compliant": count(ir_v) == 0},
		"SC": {"violations": count(sc_v), "compliant": count(sc_v) == 0},
		"SI": {"violations": count(si_v), "compliant": count(si_v) == 0},
	},
}
