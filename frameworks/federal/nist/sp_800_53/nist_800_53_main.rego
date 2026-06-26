package nist_800_53.main

import rego.v1

# NIST SP 800-53 Rev 5 — Master orchestrator.
#
# Aggregates violations from the per-family modules under
# data.nist.sp800_53.* and exports the compliance_report shape
# expected by ansible/playbooks/generic_framework_assessment.yml.
#
# OPA endpoint: POST <opa_security>/v1/data/nist_800_53/main/compliance_report
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
_ac_au       := array.concat(ac_v, au_v)
_ac_au_cm    := array.concat(_ac_au, cm_v)
_acm_ia      := array.concat(_ac_au_cm, ia_v)
_acm_ia_ir   := array.concat(_acm_ia, ir_v)
_acm_ia_ir_sc := array.concat(_acm_ia_ir, sc_v)
all_violations := array.concat(_acm_ia_ir_sc, si_v)

violations := all_violations

# Controls evaluated across all aggregated families. Update when new
# families are wired in.
total_controls := 91   # AC(18) + AU(12) + CM(11) + IA(12) + IR(9) + SC(17) + SI(13) — minus 1

compliant if { count(violations) == 0 }

# Default for fields supplied via input. Without a default, an undefined
# reference inside the object literal would make the whole report undefined
# (and the OPA endpoint would return {}).
default assessed_at := "unknown"
assessed_at := input.assessment_date

compliance_report := {
    "framework":       "NIST SP 800-53 Rev 5",
    "version":         "Rev 5",
    "regulation":      "FISMA / FedRAMP baseline reference catalog",
    "assessed_at":     assessed_at,
    "total_controls":  total_controls,
    "violations":      violations,
    "violation_count": count(violations),
    "compliant":       compliant,
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
