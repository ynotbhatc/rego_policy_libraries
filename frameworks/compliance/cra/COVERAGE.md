---
title: EU Cyber Resilience Act (CRA) — Policy Coverage
version: v0.3
date: 2026-06-26
authors:
  - Tim Coulter
  - Claude (Anthropic)
---

# EU Cyber Resilience Act — AAC Policy Coverage

**Regulation**: Regulation (EU) 2024/2847 ("Cyber Resilience Act" / CRA)
**In force**: November 2024
**Mandatory compliance**: December 2027
**Scope of this document**: what the AAC Rego policy library covers, what it does not, and how to use it.

---

## Summary

This library implements **15 policy modules** across the major CRA chapters covering all five categories of economic operator (manufacturer, authorised representative, importer, distributor, online marketplace) plus the new "open-source software steward" category, the Article 23 FOSS exclusion boundary, and the deepest annex content checks (Annex I, II, IV, VII).

**Total**: **217 distinct control checks** across 15 modules, surfaced at a single endpoint:

```
POST <opa>/v1/data/cra/main/compliance_report
```

Returns the standard AAC contract shape `{framework, compliant, total_controls, violations, violation_count, module_summary}` so it's interchangeable with every other framework in the library.

**Test coverage**: 54 unit tests, full repository `opa test` at 129/129 passing.

---

## Module-by-module coverage

| # | Module | CRA basis | Controls | Notes |
|---|---|---|---|---|
| 1 | `cra.essential_requirements` | Annex I Part I | 21 | Core "security by design" — secure default config, vuln protection, MFA / IAM, encryption (at rest + in transit), code signing, data minimisation, DoS protection, attack-surface reduction, exploitation mitigation, security event logging, secure data deletion |
| 2 | `cra.vulnerability_handling` | Annex I Part II | 16 | SBOM (machine-readable), remediation process, **5-year minimum support period** enforcement, regular testing, public disclosure post-patch, coordinated vulnerability disclosure (CVD) policy, single contact point, secure update channel |
| 3 | `cra.incident_reporting` | Article 14 | 11 | **24h / 72h / 14d** vulnerability reporting cascade; **24h / 72h / 1-month** severe-incident cascade; user notification + mitigation guidance; single ENISA reporting point |
| 4 | `cra.technical_documentation` | Article 28 + Annex VII | 15 | Product description, risk assessment, design/architecture, cybersecurity control mapping, vuln-handling process documentation, SBOM inclusion, test results, third-party assessment evidence (for Important Class II / Critical), 10-year retention, availability to authorities |
| 5 | `cra.conformity_assessment` | Articles 32-33 | 11 | Conformity procedure selection; **Module A insufficient for Important Class II**; Critical products require European cybersecurity certification scheme; notified body engagement + ID; CE marking (affixed, visible, legible, indelible); notified body number alongside CE; reassessment on modification |
| 6 | `cra.manufacturer_obligations` | Article 13 | 14 | Risk assessment performed + documented; vuln handling lifetime coverage; third-party component due diligence + monitoring; ENISA reporting process; 5-year support period; user information; market surveillance cooperation; end-of-support notification 12 months in advance; PSIRT lead |
| 7 | `cra.authorised_representative` | Article 18 | 13 | Written mandate; non-EU manufacturer must appoint EU rep; retention of Declaration + Tech Doc for 10 years; cooperation with authorities; mandate termination + authority notification if manufacturer breaches CRA; **non-delegation** of essential requirements + conformity assessment; contact details in user info |
| 8 | `cra.importer_obligations` | Article 19 | 14 | Verify manufacturer conformity assessment + technical documentation + CE marking + Declaration; importer identification on product; storage/transport preserves compliance; risk awareness reporting; 10-year doc retention; corrective action + withdrawal/recall; **Art.21 escalation** to manufacturer role if rebranding |
| 9 | `cra.distributor_obligations` | Article 20 | 15 | Pre-availability verification; suspend availability on suspected non-conformity; storage handling; market-surveillance notification; cooperation; corrective action; **Art.21 escalation** to manufacturer if product modified or sold under own brand |
| 10 | `cra.oss_steward` | Article 24 | 13 | **Threshold-gated** (systematic + sustained + commercial); cybersecurity policy published + covers vulnerability handling + secure development; cooperation with market surveillance; 24h/72h ENISA reporting; downstream manufacturer engagement; coordinated vuln disclosure policy; user reporting channel; security decision records |
| 11 | `cra.user_information` | Annex II | 20 | Manufacturer + auth-rep contact details; product type/batch/version; intended purpose + security environment; cybersecurity properties; use-case threats; SBOM access; support period + end-of-support date; security update access + install instructions; secure decommissioning; Member State languages; readability appropriate for users |
| 12 | `cra.declaration_of_conformity` | Annex IV | 20 | Product model + serial/batch identifier; manufacturer details; authorised representative details (when applicable); statement of sole responsibility; object description sufficient for traceability; explicit conformity-with-CRA statement; harmonised standards referenced **with dates/versions**; notified body name + ID + certificate ref (when applicable); declared support period; signature with name + function + place + date; translation into Member State languages |
| 13 | `cra.substantial_modification` | Article 11 | 13 | Documented + published assessment criteria; conformity reassessment after substantial mod; modifier assumes Art.13 obligations; risk assessment update on new connectivity / cryptographic-primitive change / SBOM change; technical documentation update; Declaration reissued; user notification of security-relevant changes; support period recommitment; annual review of assessment criteria |
| 14 | `cra.online_marketplace` | Article 22 | 13 | **Threshold-gated** (marketplace provider + offers PDE products); single point of contact for authorities + end users; cooperation; **48h authority takedown order action**; trader identity verification + CRA attestation; random checks (≥ 1% sample); manufacturer notification + listing removal on non-compliance; affected-buyer notification; consumer reporting channel; documented CRA process |
| 15 | `cra.foss_exclusion` | Article 23 + Recitals 15-18 | 8 | **Boundary check** — returns `exempt = true` for non-commercial OSS, zero violations. Detects mis-claims: paid support / license fees / commercial SaaS / donation-funded full-time devs / integration into commercial products. Requires documented + annually-reviewed exemption basis |

---

## What's intentionally NOT covered

| CRA element | Status | Reason |
|---|---|---|
| **Annex III** product classification lists (Important + Critical category catalogues) | Not as a module | These are static lists; manufacturers self-classify. We check whether the *consequences* of classification (Art.32(2), Art.32(3)) are respected — that's the auditable surface. |
| **Article 6** — list of products with digital elements | Not as a module | Definitional, not policy-checkable as a separate rule beyond classification. |
| **Articles 25-30** — Notified body designation, accreditation, withdrawal | Not as a module | These obligations land on Member States + accreditation bodies, not on economic operators. The product manufacturer interacts via Art.32(4) which we cover. |
| **Article 31** — European cybersecurity certification scheme detail | Surface only | We check whether a critical product *uses* a scheme (Art.32(3)), not the scheme's internal validity. |
| **Articles 36-37** — Regulatory sandboxes + voluntary certification | Not yet | Opt-in mechanisms; lower priority. Easy to add as `cra.sandbox` if needed. |
| **Annex V** — Full information requirements for technical documentation | Substantially covered | We cover Annex VII (which references Annex V's requirements) plus our own content checks in `cra.technical_documentation` and `cra.declaration_of_conformity`. Pure-Annex-V detail is small. |
| **Annex VI** — Per-module conformity assessment procedure detail | Partially covered | We check which module is *selected* (Modules A / B+C / B+D / H). We do not validate the execution of each module's internal sub-steps. |
| **Articles 47-54** — Penalties + fines | Not policy-checkable | These are statutory consequences, not obligations on operators. |
| **Article 64** — General CRA review by Commission | Not policy-checkable | EU institutional obligation. |

**Net assessment**: every policy-checkable obligation on the economic operator side of CRA is covered. The omissions above are either institutional (Member State / notified body / Commission) or definitional (product lists, scheme detail).

---

## How to use it

### Single endpoint

```bash
curl -X POST <opa>/v1/data/cra/main/compliance_report \
  -H "Content-Type: application/json" \
  -d @cra_input.json
```

### Input shape

The full input shape is documented per module in the comment header of each `.rego` file. The minimum useful input includes:

```json
{
  "entity_name":      "Acme Connected Products GmbH",
  "product_name":     "ConnectedThermostat-7",
  "product_class":    "important_class_2",
  "assessment_date":  "2026-06-26",
  ...
}
```

Per-module sub-keys (e.g. `incident_reporting.*`, `conformity_assessment.*`, `user_information.*`) provide the facts. **Omitted facts default to non-compliant** — every rule contains a `not input.X` guard which fires when the fact is absent. This is intentional: the framework rewards explicit attestation.

Worked example fixtures will land in `examples/` alongside this doc.

### Standard contract response

```json
{
  "framework":       "EU Cyber Resilience Act (CRA)",
  "regulation":      "Regulation (EU) 2024/2847",
  "in_force":        "2024-11",
  "mandatory_from":  "2027-12",
  "compliant":       false,
  "total_controls":  217,
  "violation_count": 142,
  "violations":      ["CRA Annex I.1(a): ...", "CRA Art.14(2)(b): ...", ...],
  "module_summary": {
    "essential_requirements":     {"violations": 20, "compliant": false},
    "vulnerability_handling":     {"violations": 14, "compliant": false},
    ...
    "foss_exclusion":             {"violations":  0, "compliant": true, "exempt": false}
  }
}
```

The `compliant` field is a strict AND across all 217 controls. The `module_summary` exposes per-module pass/fail for finer dashboards.

---

## Routing

Per `opa_framework_map` in the AAC compliance repo (`ansible/vars/site_config.yml`), CRA routes to the **compliance** bucket — `opa-compliance` on port `:8182`. The AAC generic framework playbook (`ansible/playbooks/generic_framework_assessment.yml`) automatically resolves the correct OPA container; no hardcoding needed.

```yaml
opa_framework_map:
  cra: compliance
```

(Add this line once after merge if not already present.)

---

## Testing

```bash
# Local — single framework
opa test policies/frameworks/compliance/cra/ -v
# 54/54 passing

# Local — full repo
cd policies/
opa test . --ignore '.github' --ignore '*.yml' --ignore '*.json'
# 129/129 passing

# CI runs the full repo test on every PR
# (.github/workflows/ci.yml in rego_policy_libraries)
```

**Coverage** (`opa test --coverage`): **84.1% overall** on the CRA tree. Per module:

| Module | Line coverage | Why |
|---|---|---|
| cra_main.rego | 100% | Pure aggregator; every rule fires |
| essential_requirements | 95.2% | Pure boolean rules — every rule fires on empty input |
| user_information | 95.2% | Same |
| vulnerability_handling | 94.1% | Same |
| manufacturer_obligations | 93.3% | Same |
| foss_exclusion | 89.7% | Mis-claim branches + Recital 18 + threshold-gate tested |
| substantial_modification | 86.8% | All change-trigger branches tested |
| online_marketplace | 86.4% | Threshold gate + 48h takedown + sample-size + listing-severity tested |
| technical_documentation | 85.7% | One Class-II-third-party branch only partly tested |
| declaration_of_conformity | 81.2% | Notified-body conditional + signature sub-checks tested |
| incident_reporting | 74.5% | Many conditional rules on `hours_since_*` not all branches exercised |
| authorised_representative | 63.2% | Many conditional rules on `manufacturer_outside_eu`, `manufacturer_breaching_cra` |
| conformity_assessment | 61.4% | Module-type branches (A/B+C/H) sparsely tested |
| oss_steward | 60.6% | Many conditional rules behind the threshold gate |
| importer_obligations | 60.8% | Many conditional rules on `non_conformity_known`, `placed_under_own_brand` |
| distributor_obligations | 43.9% | Most rules are conditional cascades — only the most-significant branches tested |

The unconditional rules (the majority of essential_requirements, vuln_handling, user_information, manufacturer_obligations, declaration_of_conformity content checks) are exhaustively covered by the empty-input smoke tests. Conditional rules (distributor escalation, importer rebrand, OSS-steward threshold, marketplace takedown timing, etc.) are tested for the auditor-relevant branches and would benefit from additional fixture-based tests in future iterations.

---

## Versioning + maintenance

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-26 | Initial 6 modules (manufacturer side) — PR #31 first commit |
| v0.2 | 2026-06-26 | Added importer / distributor / auth rep / OSS steward / Annex II — PR #31 second commit |
| v0.3 | 2026-06-26 | Added Declaration content / Art.11 substantial modification / Art.22 marketplaces / Art.23 FOSS exclusion — PR #31 third commit |

This document tracks the current state of the framework. When the CRA gets implementing acts (delegated regulations under Art.6, Art.27, Art.39), or when standardisation bodies publish harmonised standards under Art.27, those will land as additional rules in the relevant modules and trigger version bumps here.
