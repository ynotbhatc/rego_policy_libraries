package nist_csf.main

import rego.v1

# NIST Cybersecurity Framework 2.0 — Master orchestrator.
#
# Aggregates violations across all six CSF 2.0 functions and exports
# the compliance_report shape expected by ansible/playbooks/generic_framework_assessment.yml.
#
# OPA endpoint: POST <opa_security>/v1/data/nist_csf/main/compliance_report
#
# Functions aggregated:
#   GV — Govern   (existing module)
#   ID — Identify (new)
#   PR — Protect  (existing module — AC subset)
#   DE — Detect   (new)
#   RS — Respond  (new)
#   RC — Recover  (new)

import data.nist.csf.govern   as gv
import data.nist.csf.identify as id_
import data.nist.csf.protect  as pr
import data.nist.csf.detect   as de
import data.nist.csf.respond  as rs
import data.nist.csf.recover  as rc

default compliant := false

gv_v := [v | some v in gv.violation]
id_v := [v | some v in id_.violation]
pr_v := [v | some v in pr.violation]
de_v := [v | some v in de.violation]
rs_v := [v | some v in rs.violation]
rc_v := [v | some v in rc.violation]

# Nested 2-arg array.concat per repo convention
_gv_id    := array.concat(gv_v, id_v)
_gv_id_pr := array.concat(_gv_id, pr_v)
_gv_id_pr_de := array.concat(_gv_id_pr, de_v)
_gv_id_pr_de_rs := array.concat(_gv_id_pr_de, rs_v)
all_violations := array.concat(_gv_id_pr_de_rs, rc_v)

violations := all_violations

# Total controls evaluated across functions. Reflects the violation rules
# present in each module — update when adding/removing rules.
total_controls := 87   # GV(15) + ID(17) + PR(15) + DE(18) + RS(16) + RC(6)

compliant if { count(violations) == 0 }

default assessed_at := "unknown"
assessed_at := input.assessment_date

compliance_report := {
    "framework":       "NIST Cybersecurity Framework 2.0",
    "version":         "2.0",
    "assessed_at":     assessed_at,
    "total_controls":  total_controls,
    "violations":      violations,
    "violation_count": count(violations),
    "compliant":       compliant,
    "function_summary": {
        "govern":   {"violations": count(gv_v), "compliant": count(gv_v) == 0},
        "identify": {"violations": count(id_v), "compliant": count(id_v) == 0},
        "protect":  {"violations": count(pr_v), "compliant": count(pr_v) == 0},
        "detect":   {"violations": count(de_v), "compliant": count(de_v) == 0},
        "respond":  {"violations": count(rs_v), "compliant": count(rs_v) == 0},
        "recover":  {"violations": count(rc_v), "compliant": count(rc_v) == 0},
    },
}
