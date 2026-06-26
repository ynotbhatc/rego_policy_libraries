package fedramp.main

import rego.v1
import data.fedramp as f

# FedRAMP main adapter — exposes the standard contract
# (compliance_report, violations, compliant) at /v1/data/fedramp/main/...
# on top of the existing `package fedramp` policy module, which uses
# its own names (fedramp_compliant, all_violations, fedramp_compliance_report).
#
# Generic playbook contract:
#   /v1/data/fedramp/main/compliance_report
#
# The upstream module's fedramp_compliance_report references input fields
# (impact_level, etc.) directly, so it goes undefined on empty input.
# We compute the area summary here from the upstream violation_* sets so
# the adapter's compliance_report is always defined.

default compliant := false
default impact_level := "unknown"
default assessed_at := "unknown"

compliant := f.fedramp_compliant

impact_level := input.impact_level
assessed_at := input.assessment_date

violations := f.all_violations

# Per-area summaries — recomputed locally instead of pulling from the
# upstream report (which is input-dependent).
area_summary := {
    "authorization":           {"violations": count(f.violation_authorization),  "compliant": count(f.violation_authorization)  == 0},
    "cryptography":            {"violations": count(f.violation_crypto),         "compliant": count(f.violation_crypto)         == 0},
    "data_residency":          {"violations": count(f.violation_data_residency), "compliant": count(f.violation_data_residency) == 0},
    "personnel_security":      {"violations": count(f.violation_personnel),      "compliant": count(f.violation_personnel)      == 0},
    "continuous_monitoring":   {"violations": count(f.violation_conmon),         "compliant": count(f.violation_conmon)         == 0},
    "third_party_assessment":  {"violations": count(f.violation_3pao),           "compliant": count(f.violation_3pao)           == 0},
    "supply_chain":            {"violations": count(f.violation_scrm),           "compliant": count(f.violation_scrm)           == 0},
}

# FedRAMP control counts vary by impact level (Low: ~125, Moderate: ~325,
# High: ~421). Reported here as the baseline summary.
default total_controls := 325   # Moderate baseline (most common for cloud services)
total_controls := 125 if impact_level == "low"
total_controls := 325 if impact_level == "moderate"
total_controls := 421 if impact_level == "high"

compliance_report := {
    "framework":       "FedRAMP",
    "regulation":      "Federal Risk and Authorization Management Program",
    "baseline":        "NIST SP 800-53 Rev 5 + FedRAMP overlays",
    "impact_level":    impact_level,
    "assessed_at":     assessed_at,
    "compliant":       compliant,
    "violations":      violations,
    "violation_count": count(violations),
    "total_controls":  total_controls,
    "area_summary":    area_summary,
}
