package cra.main

import rego.v1

# EU Cyber Resilience Act (CRA) — Master orchestrator.
#
# Regulation (EU) 2024/2847. Entered into force November 2024;
# mandatory compliance for products with digital elements (PDE) placed
# on the EU market from December 2027.
#
# Applies to:
#   - Manufacturers           (Art.13)
#   - Authorised representatives (Art.18)
#   - Importers               (Art.19)
#   - Distributors            (Art.20)
#   - Open-source stewards    (Art.24 — new CRA category)
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
#   Article 18       — Authorised representative obligations        (data.cra.authorised_representative)
#   Article 19       — Importer obligations                         (data.cra.importer_obligations)
#   Article 20       — Distributor obligations                      (data.cra.distributor_obligations)
#   Article 24       — Open-source software steward obligations     (data.cra.oss_steward)
#   Annex II         — User information                             (data.cra.user_information)

import data.cra.essential_requirements      as er
import data.cra.vulnerability_handling      as vh
import data.cra.incident_reporting          as ir
import data.cra.technical_documentation     as td
import data.cra.conformity_assessment       as ca
import data.cra.manufacturer_obligations    as mo
import data.cra.authorised_representative   as ar
import data.cra.importer_obligations        as io_
import data.cra.distributor_obligations     as do_
import data.cra.oss_steward                 as oss
import data.cra.user_information            as ui

default compliant := false
default entity_name := "unknown"
default product_name := "unknown"
default product_class := "unknown"
default assessed_at := "unknown"

entity_name   := input.entity_name
product_name  := input.product_name
product_class := input.product_class
assessed_at   := input.assessment_date

er_v  := [v | some v in er.violation]
vh_v  := [v | some v in vh.violation]
ir_v  := [v | some v in ir.violation]
td_v  := [v | some v in td.violation]
ca_v  := [v | some v in ca.violation]
mo_v  := [v | some v in mo.violation]
ar_v  := [v | some v in ar.violation]
io_v  := [v | some v in io_.violation]
do_v  := [v | some v in do_.violation]
oss_v := [v | some v in oss.violation]
ui_v  := [v | some v in ui.violation]

# Nested 2-arg array.concat per repo convention.
_a  := array.concat(er_v, vh_v)
_b  := array.concat(_a, ir_v)
_c  := array.concat(_b, td_v)
_d  := array.concat(_c, ca_v)
_e  := array.concat(_d, mo_v)
_f  := array.concat(_e, ar_v)
_g  := array.concat(_f, io_v)
_h  := array.concat(_g, do_v)
_i  := array.concat(_h, oss_v)
all_violations := array.concat(_i, ui_v)

violations := all_violations

# Control counts per module (also documented in each module's compliance_report).
#   Annex I Part I    essential_requirements    21
#   Annex I Part II   vulnerability_handling    16
#   Article 14        incident_reporting        11
#   Article 28/VII    technical_documentation   15
#   Articles 32-33    conformity_assessment     11
#   Article 13        manufacturer_obligations  14
#   Article 18        authorised_representative 13
#   Article 19        importer_obligations      14
#   Article 20        distributor_obligations   15
#   Article 24        oss_steward               13
#   Annex II          user_information          20
# Total: 163 distinct control checks.
total_controls := 163

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
        "essential_requirements":     {"violations": count(er_v),  "compliant": count(er_v)  == 0},
        "vulnerability_handling":     {"violations": count(vh_v),  "compliant": count(vh_v)  == 0},
        "incident_reporting":         {"violations": count(ir_v),  "compliant": count(ir_v)  == 0},
        "technical_documentation":    {"violations": count(td_v),  "compliant": count(td_v)  == 0},
        "conformity_assessment":      {"violations": count(ca_v),  "compliant": count(ca_v)  == 0},
        "manufacturer_obligations":   {"violations": count(mo_v),  "compliant": count(mo_v)  == 0},
        "authorised_representative":  {"violations": count(ar_v),  "compliant": count(ar_v)  == 0},
        "importer_obligations":       {"violations": count(io_v),  "compliant": count(io_v)  == 0},
        "distributor_obligations":    {"violations": count(do_v),  "compliant": count(do_v)  == 0},
        "oss_steward":                {"violations": count(oss_v), "compliant": count(oss_v) == 0},
        "user_information":           {"violations": count(ui_v),  "compliant": count(ui_v)  == 0},
    },
}
