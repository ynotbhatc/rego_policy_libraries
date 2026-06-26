package cra.main

import rego.v1

# EU Cyber Resilience Act (CRA) — Master orchestrator.
#
# Regulation (EU) 2024/2847. Entered into force November 2024;
# mandatory compliance for products with digital elements (PDE) placed
# on the EU market from December 2027.
#
# Applies to:
#   - Manufacturers
#   - Importers
#   - Distributors
#   of products with digital elements (hardware + software with data
#   connectivity capability).
#
# Product classification (Article 7 + Annex III):
#   - Default (most products)
#   - Important — Class I
#   - Important — Class II  (third-party conformity assessment required)
#   - Critical               (European cybersecurity certification scheme)
#
# OPA endpoint: POST <opa_compliance>/v1/data/cra/main/compliance_report
#
# Sub-modules aggregated:
#   Annex I Part I   — Essential cybersecurity requirements         (data.cra.essential_requirements)
#   Annex I Part II  — Vulnerability handling                       (data.cra.vulnerability_handling)
#   Article 14       — Incident reporting (24h / 72h / final)       (data.cra.incident_reporting)
#   Article 28 / VII — Technical documentation                      (data.cra.technical_documentation)
#   Articles 32-33   — Conformity assessment + CE marking           (data.cra.conformity_assessment)
#   Article 13       — Manufacturer obligations                     (data.cra.manufacturer_obligations)

import data.cra.essential_requirements    as er
import data.cra.vulnerability_handling    as vh
import data.cra.incident_reporting        as ir
import data.cra.technical_documentation   as td
import data.cra.conformity_assessment     as ca
import data.cra.manufacturer_obligations  as mo

default compliant := false
default entity_name := "unknown"
default product_name := "unknown"
default product_class := "unknown"
default assessed_at := "unknown"

entity_name   := input.entity_name
product_name  := input.product_name
product_class := input.product_class
assessed_at   := input.assessment_date

er_v := [v | some v in er.violation]
vh_v := [v | some v in vh.violation]
ir_v := [v | some v in ir.violation]
td_v := [v | some v in td.violation]
ca_v := [v | some v in ca.violation]
mo_v := [v | some v in mo.violation]

# Nested 2-arg array.concat per repo convention.
_er_vh             := array.concat(er_v, vh_v)
_er_vh_ir          := array.concat(_er_vh, ir_v)
_er_vh_ir_td       := array.concat(_er_vh_ir, td_v)
_er_vh_ir_td_ca    := array.concat(_er_vh_ir_td, ca_v)
all_violations     := array.concat(_er_vh_ir_td_ca, mo_v)

violations := all_violations

# 21 + 16 + 11 + 15 + 11 + 14 = 88 control checks across the six modules.
total_controls := 88

compliant if { count(violations) == 0 }

compliance_report := {
    "framework":       "EU Cyber Resilience Act (CRA)",
    "regulation":      "Regulation (EU) 2024/2847",
    "in_force":        "2024-11",
    "mandatory_from":  "2027-12",
    "entity_name":     entity_name,
    "product_name":    product_name,
    "product_class":   product_class,
    "assessed_at":     assessed_at,
    "compliant":       compliant,
    "total_controls":  total_controls,
    "violations":      violations,
    "violation_count": count(violations),
    "module_summary": {
        "essential_requirements":   {"violations": count(er_v), "compliant": count(er_v) == 0},
        "vulnerability_handling":   {"violations": count(vh_v), "compliant": count(vh_v) == 0},
        "incident_reporting":       {"violations": count(ir_v), "compliant": count(ir_v) == 0},
        "technical_documentation":  {"violations": count(td_v), "compliant": count(td_v) == 0},
        "conformity_assessment":    {"violations": count(ca_v), "compliant": count(ca_v) == 0},
        "manufacturer_obligations": {"violations": count(mo_v), "compliant": count(mo_v) == 0},
    },
}
