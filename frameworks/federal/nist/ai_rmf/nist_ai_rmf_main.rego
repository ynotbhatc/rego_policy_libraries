package nist_ai_rmf.main

import rego.v1
import data.nist.ai_rmf as ai

# NIST AI RMF main adapter — exposes the standard contract
# (compliance_report, violations, compliant) at
# /v1/data/nist_ai_rmf/main/compliance_report
# on top of the existing `package nist.ai_rmf` module.

default compliant := false
default ai_system_name := "unknown"
default assessed_at := "unknown"

compliant := ai.ai_rmf_compliant

ai_system_name := input.ai_system.name
assessed_at := input.assessment_date

violations := ai.all_violations

# Per-function summary computed locally (upstream's ai_rmf_compliance_report
# references input.ai_system.name so it goes undefined on empty input).
function_summary := {
    "GOVERN":  {"violations": count(ai.violation_govern),          "compliant": count(ai.violation_govern)          == 0},
    "MAP":     {"violations": count(ai.violation_map),             "compliant": count(ai.violation_map)             == 0},
    "MEASURE": {"violations": count(ai.violation_measure),         "compliant": count(ai.violation_measure)         == 0},
    "MANAGE":  {"violations": count(ai.violation_manage),          "compliant": count(ai.violation_manage)          == 0},
    "TRUSTWORTHINESS": {"violations": count(ai.violation_trustworthiness), "compliant": count(ai.violation_trustworthiness) == 0},
}

# AI RMF 1.0 spans 4 core functions (GOVERN, MAP, MEASURE, MANAGE), each with
# multiple categories. Reference catalog has ~70 categories/subcategories.
total_controls := 70

compliance_report := {
    "framework":       "NIST AI Risk Management Framework (AI RMF)",
    "version":         "1.0",
    "published":       "2023-01",
    "ai_system":       ai_system_name,
    "assessed_at":     assessed_at,
    "compliant":       compliant,
    "violations":      violations,
    "violation_count": count(violations),
    "total_controls":  total_controls,
    "function_summary": function_summary,
}
