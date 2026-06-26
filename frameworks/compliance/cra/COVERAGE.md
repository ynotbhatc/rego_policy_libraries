---
title: EU Cyber Resilience Act (CRA) — Policy Coverage
version: v0.5
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

This library implements **17 policy modules** across the major CRA chapters covering all five categories of economic operator (manufacturer, authorised representative, importer, distributor, online marketplace) plus the new "open-source software steward" category, the Article 23 FOSS exclusion boundary, the deepest annex content checks (Annex I, II, IV, VII), and **two evidence-integration bridges** that re-frame existing SLSA supply-chain + ISO 27001 cryptography findings as CRA citations — no double-attestation required.

**Total**: **244 distinct control checks** across 17 modules, surfaced at a single endpoint:

```
POST <opa>/v1/data/cra/main/compliance_report
```

Returns the standard AAC contract shape `{framework, compliant, total_controls, violations, violation_count, module_summary}` so it's interchangeable with every other framework in the library.

**Test coverage**: 65 unit tests, full repository `opa test` at 139/139 passing.

---

## Business case

### Why CRA matters

The Cyber Resilience Act is the **first horizontal EU cybersecurity law for products**. It patches a regulatory gap: GDPR governs personal data, NIS2 governs essential service operators, but until CRA there was no EU-wide obligation on the products themselves — the connected thermostats, industrial controllers, smart-home cameras, and the embedded software running everywhere in between. Estimated affected market: **roughly 50,000+ products** sold into the EU, across every manufacturer with a CE marking obligation.

Three CRA properties make it consequential:

1. **Penalties are turnover-linked, not absolute.** A small manufacturer can absorb a flat €1M fine. A €5B-revenue manufacturer cannot absorb 2.5% of global annual turnover (€125M) — which is what an Annex I essential-requirements failure exposes them to (Article 53).
2. **Liability cascades through the supply chain.** Importers and distributors carry their own obligation sets (Articles 19-20) and inherit manufacturer liability when they rebrand or modify (Article 21). A failure upstream contaminates everyone who handled the product downstream.
3. **The 24-hour clock is unforgiving.** Article 14 requires early-warning notification to ENISA within 24 hours of awareness of an actively exploited vulnerability. There is no "we'll handle it Monday" window. Organisations without a documented, tested process miss the deadline by default.

### What this framework gives you

A continuously-evaluable, evidence-producing CRA compliance signal. Not a checklist someone fills in once and forgets — a queryable system that:

- **Says whether you're compliant right now**, on every one of the 15 obligation surfaces CRA covers, against a documented fact set you supply.
- **Says specifically what's missing** when you're not — by article + annex reference, in language an auditor or notified body recognises.
- **Produces an audit trail** — each query returns a structured `compliance_report` with the violation list, timestamp, and module pass/fail. Store the report and you have an answer to "what did you know on date X?"
- **Decouples claim from check** — your engineers attest to facts (SBOM published / 24h early warning sent / Module H selected); the Rego policy evaluates whether those facts add up to CRA conformity. No more spreadsheet attestations that nobody validates.

### Where the value lands

| Use case | What this framework changes |
|---|---|
| **Pre-launch product gate** | A product that fails this report at launch ships with a known compliance failure. Catching it in CI is hours of work; catching it post-CE-marking is a recall + a fine. Run the report as a gate in the product release pipeline. |
| **Continuous monitoring** | Run nightly over your product portfolio. SBOMs change, support periods get re-evaluated, vulnerabilities get disclosed. A monthly drift report is the difference between knowing about a problem in week 2 vs. month 6. |
| **Supplier due diligence** | If you're an importer or distributor, run the report against your supplier's attested facts before accepting a shipment. Article 19/20 makes you liable for what you place on the market — verifying upstream protects you. |
| **Acquisition due diligence** | Buying a company with EU-market products? Run the report against the target's product portfolio. Surfaces the inherited liability before the deal closes. |
| **Incident-triggered re-assessment** | Vulnerability disclosed in a component you ship. Re-run the report with the new vulnerability marked as actively exploited. The framework tells you what the 24h / 72h / 14d clock looks like and which reports are now overdue. |
| **Audit + notified body prep** | Before a Module H assessment or a market surveillance audit, run the report. Hand over the JSON + audit trail. Reduces the "discovery" phase of the audit by weeks. |
| **Insurance underwriting** | Cyber insurance carriers are pricing CRA exposure. A continuously-running compliance report is the difference between "self-attested compliant" (untrusted) and "evidence-producing compliant" (premium reduction). |

---

## What the framework identifies (risk categories)

The 217 control checks group into **eight risk categories**, listed roughly in descending order of typical enforcement priority. The right-hand column lists the modules that produce findings in each.

| Risk category | What it catches | Modules |
|---|---|---|
| **Essential requirements gap** | Product missing CRA "by design" controls — no MFA, weak/missing encryption, no secure default config, no code signing, attack-surface bloat, missing exploitation mitigations. The Annex I rules. | essential_requirements, manufacturer_obligations |
| **Reporting timeline failure** | Manufacturer / OSS steward missed the 24-hour early warning, the 72-hour notification, or the 14-day final report. Or: severe-incident clock missed. Or: impacted users not informed. | incident_reporting, oss_steward |
| **Support period under-commitment** | Declared support period below the 5-year CRA minimum. Or: support period declared but no end-of-support date communicated to users. Or: no plan for the 12-month-prior end-of-support notification. | vulnerability_handling, manufacturer_obligations, user_information |
| **Documentation gap** | Technical documentation incomplete; Declaration of Conformity missing required Annex IV elements (statement of sole responsibility, explicit CRA citation, harmonised standards with versions, signature with function); 10-year retention not in place. | technical_documentation, declaration_of_conformity, manufacturer_obligations |
| **Conformity assessment mismatch** | Product classified Important Class II but Module A used (must be B+C, B+D, or H). Critical product not certified under a European cybersecurity certification scheme. Notified body engaged but ID not recorded. CE marking absent / incomplete. | conformity_assessment, declaration_of_conformity |
| **Supply-chain liability** | Manufacturer outside EU but no authorised representative appointed. Importer placing under own brand without assuming manufacturer obligations. Distributor modifying without re-assessment. Marketplace not actioning takedown orders within 48 hours. Mis-claimed FOSS exclusion. | authorised_representative, importer_obligations, distributor_obligations, online_marketplace, foss_exclusion |
| **Substantial-modification trigger ignored** | Connectivity added, cryptographic primitive changed, or SBOM altered, but no risk assessment refresh, no conformity reassessment, no Declaration reissue. Modifier silently assumed manufacturer liability without recognising it. | substantial_modification |
| **User information gap** | Annex II content missing — manufacturer contact for vuln reports absent, support period not disclosed, end-of-support date not disclosed, secure decommissioning guidance not provided, user info not in the right Member State languages. | user_information, declaration_of_conformity |

For each risk category, the framework returns the **specific article or annex citation** that an auditor will recognise, not a generic "compliance failure" message. Example output excerpts:

```
CRA Annex I.5(b): Transmitted data not protected via state-of-the-art encryption
CRA Art.14(2)(a): No early warning sent to ENISA/CSIRT within 24h (current: 36h since awareness)
CRA Art.32(2): Important Class II products require Module B+C, B+D, or H — Module A is insufficient
CRA Art.13(8): Declared support period (3 years) is below the 5-year minimum
CRA Art.21: Importer placing the product under its own name/trademark has not assumed manufacturer obligations under Article 13
CRA Annex IV.7: Declaration references harmonised standards but does not include their dates/versions
```

These messages are intentionally written for auditors, not for engineers. They're the language that appears in a notified body's findings letter or a market surveillance correction notice.

---

## Penalty exposure + risk reduction

### EU fine tiers (Articles 53-54)

CRA establishes a three-tier penalty structure. Maximum fines are the **greater** of the listed absolute amount or the percentage of global annual turnover.

| Tier | Violation type | Maximum fine |
|---|---|---|
| **Tier 1** (most severe) | Failure to comply with **essential requirements** (Annex I); failure of **manufacturer obligations** under Article 13; placing on the market without conformity assessment | **€15M or 2.5% of global annual turnover** |
| **Tier 2** | Failure of other obligations (importer Art.19, distributor Art.20, authorised representative Art.18, reporting Art.14, technical documentation Art.28, etc.) | **€10M or 2% of global annual turnover** |
| **Tier 3** | Supplying incorrect, incomplete, or misleading information to a notified body or market surveillance authority | **€5M or 1% of global annual turnover** |

Member States also set their own additional penalties, and may impose periodic penalty payments to compel compliance. For SMEs, Article 54 directs Member States to consider proportionality — but the upper bounds remain.

### What the framework reduces

| Risk | How the framework reduces it |
|---|---|
| **Tier 1 essential-requirements fine** | Continuous Annex I evaluation. Missing essential requirements surface in the report immediately; remediation happens before market placement. Reduces the probability of the failure existing AT market placement (the moment liability attaches). |
| **Tier 1 manufacturer-obligation fine** | Article 13 obligations (risk assessment, support period, third-party component due diligence, end-of-support notice planning) all evaluated. A green report = documented evidence the manufacturer can produce to authorities. |
| **Tier 2 reporting-timeline fine** | The 24h / 72h / 14d cascade rules trigger automatically at the hour-boundary. Wire the report into an alerting system and the framework tells you the report is overdue **before** it actually is. |
| **Tier 2 supply-chain fine** | Importer + distributor + authorised-representative obligations evaluated each time the supply chain handles a new product. Catches the "we didn't realise we were now the manufacturer" Article 21 trap. |
| **Tier 2 documentation fine** | Annex IV + Annex VII content checked at the field level. A Declaration of Conformity missing the explicit CRA citation, or technical documentation missing third-party assessment evidence for a Class II product, surfaces as a specific violation. |
| **Tier 3 misleading-information fine** | The framework produces evidence the manufacturer attested to. If facts later prove false, the audit trail records what was claimed when. Doesn't prevent fraud — but converts "we didn't know" into a documented chain. |
| **Market-access loss** | A Class II product with the wrong conformity assessment module cannot legally carry a CE marking. The framework catches the mismatch **before** the Declaration of Conformity is signed and before the product hits market. Cheaper to fix in design than to recall. |
| **Recall liability** | Articles 41-45 give market surveillance authorities recall powers. A product that fails post-market because of a known-but-unaddressed essential-requirements gap exposes the manufacturer to recall costs plus the underlying fine. The framework's continuous monitoring detects the gap during pre-launch QA. |
| **Reputational damage** | Public enforcement actions are listed by the EU. Avoiding a finding letter avoids the public record. |
| **Customer-contract liability** | Most enterprise customers will (post-2027) require CRA conformity attestations in supplier contracts. A continuously-running framework produces the attestation evidence; an annual self-attestation does not. |

### What the framework does NOT do

Honest scoping — the framework is a self-assessment tool, not a magic compliance machine:

- **It does not replace notified body assessment.** Important Class II and Critical products require third-party conformity assessment under Article 32. The framework helps you arrive at that assessment with a clean baseline; it does not perform the assessment.
- **It does not generate technical documentation.** Annex VII still requires you to write the documentation. The framework checks that you have the right elements; it does not produce them.
- **It does not auto-file ENISA reports.** When Article 14 timelines fire, the framework tells you the report is overdue. You still need to actually file it through the ENISA single reporting platform (Article 14(7)).
- **It does not interpret legal ambiguity.** Some CRA concepts (the Article 23 "outside the course of a commercial activity" boundary for FOSS, what counts as a "substantial modification" under Article 11) are fact-specific judgement calls. The framework evaluates the most defensible interpretation and flags the boundary cases; it does not give you legal advice.
- **It does not protect against bad-faith attestation.** If your engineers tell the framework you have MFA enforced when you don't, the framework will report compliant. It's an attestation evaluator, not an attestation verifier. Pair it with independent technical evidence (test results, SBOM scans, penetration test reports) for high-assurance use cases.

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
| 16 | `cra.supply_chain_evidence` | **Evidence bridge** — re-uses `data.supply_chain.slsa` | 14 | Consumes SLSA findings (SBOM completeness, machine-readable format, signing, CVE policy, provenance) and re-frames them in CRA citation form. The same evidence powers both an SLSA report and a CRA report — no double-attestation. Connects: Annex I.6 (integrity), Annex II.1 (SBOM), Annex II.4 (CVE disclosure), Art.13(6) (third-party diligence), Art.11 (substantial-modification SBOM refresh), Annex VII.3 (provenance in technical documentation) |
| 17 | `cra.crypto_evidence` | **Evidence bridge** — re-uses `data.iso27001.cryptography` | 13 | Consumes ISO 27001 A.10 crypto findings (policy, key management, generation, distribution, usage, destruction) and re-frames them as CRA Annex I.5 / I.6 / I.4 citations. Adds CRA-specific weak-cipher + deprecated-protocol + anti-rollback + hardware-backed-key-storage rules that ISO 27001 leaves implicit |

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

### Worked operational scenarios

**Scenario A — Pre-launch product gate**

Acme is preparing to launch ConnectedThermostat-7 (Important Class II). Engineering attests to the product facts and runs the report as a release-gate check.

The framework reports 71 violations: missing SBOM in machine-readable format, support period declared at 3 years, Module A selected (insufficient for Class II), and 18 essential-requirements gaps. Release blocked. Engineering remediates in 4 weeks pre-launch. Cost: 4 engineering-weeks. Without the gate: product ships, market surveillance flags during routine inspection 6 months in, Tier 1 fine + recall. Avoided cost: €15M floor under Article 53(2)(a), plus recall.

**Scenario B — Distributor due diligence**

A distributor receives a 10,000-unit shipment of smart cameras from a non-EU manufacturer. Before making the cameras available on the EU market, the distributor runs the report against the manufacturer's attested facts.

The framework flags: Declaration of Conformity missing the explicit Article 13 citation (Annex IV.6 violation), notified body ID not recorded in the Declaration (Annex IV.8), and importer identification absent from the product packaging (Art.20(1)(c)). The distributor refuses the shipment under Article 20(2) ("suspend availability when non-conformity suspected"). Avoided: Article 20 violation + chain-of-liability exposure if the cameras had been distributed and later found non-conformant.

**Scenario C — OSS foundation crossing the commercial line**

An OSS foundation that has historically operated under the Article 23 exclusion accepts its first commercial paid-support contract. The legal team runs the report.

The framework flags: `CRA Art.23 (mis-claim): FOSS exemption claimed, but the entity offers paid support — this is a commercial activity` and `Art.23 (boundary): Donation-funded full-time paid developers move the entity toward the OSS-steward category (Art.24)`. The foundation now knows it has crossed the boundary and has 12 months to either restructure (revert to non-commercial) or assume Article 24 OSS-steward obligations. Avoided: silent drift across the line, followed by Article 24 violations going undetected until enforcement.

**Scenario D — Active exploitation incident**

PSIRT receives credible evidence on Monday 09:00 UTC that a vulnerability in shipped firmware is being actively exploited. Continuous monitoring runs the report every 6 hours with the new incident facts.

At hour 25 (Tuesday 10:00 UTC), the framework flags `Art.14(2)(a): No early warning sent to ENISA/CSIRT within 24h (current: 25h since awareness)`. Alerting fires. ENISA notification follows within the next 30 minutes. Without the framework: the PSIRT process might have caught the deadline; might not have. The framework's clock-based rules guarantee the team is told. Avoided: Tier 2 fine for Article 14 breach (up to €10M or 2% turnover).

**Scenario E — Substantial modification escalation**

Product team adds Bluetooth Low Energy connectivity to ConnectedThermostat-7 as a v2.1 feature update. They run the report against the modified product before release.

The framework flags: `Art.11 (Annex I.1 interaction): New network connectivity added without an updated cybersecurity risk assessment`, `Art.11(2): A modification was classified as substantial but conformity assessment has not been re-performed`, and `Art.11(2) / Annex IV: Substantial modification performed but Declaration of Conformity not reissued`. Product team scopes a Module-H reassessment with the notified body. Avoided: a v2.1 product that fails Article 11 conformity by silently inheriting v2.0's declaration — a Tier 1 violation under Article 53(2)(a) because the v2.1 product is effectively unauthorised.

---

## Cross-framework mapping

Most organisations that have CRA exposure also maintain compliance against the framework set below. The same input fact (MFA enforced, encryption at rest, SBOM published, etc.) can satisfy a CRA control AND a NIST CSF / ISO 27001 / NIST 800-53 / NIS2 control simultaneously. This mapping converts the "82 new CRA controls to track" framing into "you already cover 60-70% via existing programs."

The right-hand columns are the **specific control or article reference** from each adjacent framework — not a fuzzy "see also."

### CRA Annex I Part I — Essential cybersecurity requirements

| CRA control | ISO 27001:2022 | NIST CSF 2.0 | NIST 800-53 Rev 5 | NIS2 | Implementation evidence reuse |
|---|---|---|---|---|---|
| Annex I.1(a) — Security by design / threat model | A.5.7, A.8.25 | PR.IP-2 (SDLC) | SA-11, SA-15, RA-3 | Art.21(2)(a) risk analysis | Manual attestation |
| Annex I.2(a) — Secure default configuration | A.8.9 | PR.IP-1 (baseline) | CM-2, CM-6 | Art.21(2)(i) hygiene | CIS Benchmarks for the runtime OS |
| Annex I.3(a/b) — Security updates separable + automatic | A.8.32 | PR.IP-12 (vuln mgmt) | SI-2 | Art.21(2)(b) incident handling | CICD pipeline + SLSA provenance |
| Annex I.4 — State-of-the-art authentication | A.5.16, A.5.17, A.8.5 | PR.AC-7 | IA-2, IA-2(1)(2) | Art.21(2)(j) MFA | `cra.crypto_evidence` + governance/oidc |
| Annex I.5(a) — Data at rest encryption | A.8.24 | PR.DS-1 | SC-28, SC-28(1) | Art.21(2)(h) cryptography | `cra.crypto_evidence` (ISO 27001 A.10) |
| Annex I.5(b) — Data in transit encryption | A.8.24 | PR.DS-2 | SC-8, SC-8(1) | Art.21(2)(h) | `cra.crypto_evidence` |
| Annex I.6(a) — Code/config integrity (signing) | A.8.6 | PR.DS-6 | SC-13, SI-7 | Art.21(2)(e) secure dev | `cra.supply_chain_evidence` (SLSA signing) |
| Annex I.6(b) — Tamper detection / anti-rollback | A.8.31 | PR.DS-6 | SI-7(1), SC-7 | Art.21(2)(e) | `cra.crypto_evidence` |
| Annex I.7 — Data minimisation | A.8.10, A.8.11 | PR.DS-5 | SA-8(5) | (GDPR Art.5(1)(c) overlap) | GDPR framework |
| Annex I.8 — Availability / DoS protection | A.8.6, A.5.30 | PR.IP-9 (continuity) | SC-5, CP-2 | Art.21(2)(c) continuity | NIS2 + ISO 22301 |
| Annex I.9 — Attack-surface reduction | A.8.9, A.8.27 | PR.IP-1 | CM-7, CM-7(1) | Art.21(2)(a) | CIS Benchmarks |
| Annex I.10 — Exploitation mitigation | A.8.30 | PR.PT-3 | SI-16, SI-2(6) | Art.21(2)(e) | OS hardening (CIS) |
| Annex I.11 — Security event logging | A.8.15, A.8.16 | DE.AE-3, DE.CM-1 | AU-2, AU-3, AU-6 | Art.21(2)(b) | NIST CSF Detect + NIST 800-53 AU |

### CRA Annex I Part II — Vulnerability handling

| CRA control | ISO 27001:2022 | NIST CSF 2.0 | NIST 800-53 Rev 5 | NIS2 | Implementation evidence reuse |
|---|---|---|---|---|---|
| Annex II.1 — SBOM maintained, machine-readable, components documented | A.8.30 | ID.RA-1, PR.IP-2 | SR-4, SR-4(1)(3) | Art.21(2)(d) supply chain | `cra.supply_chain_evidence` (SLSA SBOM) |
| Annex II.2 — Remediation process, security updates free, ≥5yr support | A.8.8 | PR.IP-12, RS.MI-3 | SI-2, RA-5 | Art.21(2)(b) | `cra.supply_chain_evidence` (CVE policy) |
| Annex II.3 — Regular vulnerability testing | A.8.29 | DE.CM-8 | RA-5, CA-8 | Art.21(2)(f) effectiveness | SLSA + pen-test evidence |
| Annex II.4 — Public disclosure post-patch + CVE IDs | A.5.23, A.5.25 | RS.CO-3, RS.CO-5 | IR-6, SI-5 | Art.21(2)(b) | `cra.supply_chain_evidence` |
| Annex II.5 — Coordinated vulnerability disclosure policy | A.6.7 | RS.CO-1 | IR-8 | Art.21(2)(b) | Manual policy + PSIRT |
| Annex II.6 — User vuln reporting channel | A.5.30, A.6.6 | RS.CO-2 | IR-6, AC-2(11) | Art.21(2)(b) | Manual |
| Annex II.7 — Secure update distribution channel | A.8.31 | PR.IP-3 | CM-3(2), SC-7(8) | Art.21(2)(e) | CICD + signing |

### CRA Article 13 — Manufacturer obligations

| CRA control | ISO 27001:2022 | NIST CSF 2.0 | NIST 800-53 Rev 5 | NIS2 |
|---|---|---|---|---|
| Art.13(1-3) — Essential req compliance + risk assessment | A.6.1, Clause 6.1.2 | GV.RM, ID.RA | RA-3, PM-9 | Art.21(2)(a) |
| Art.13(6) — Third-party component due diligence + vuln monitoring | A.5.19, A.5.21, A.8.30 | ID.SC-2, ID.SC-4 | SR-3, SR-6, SR-11 | Art.21(2)(d) |
| Art.13(7) — ENISA reporting process documented | A.5.24, A.5.25 | RS.CO-2, RS.CO-3 | IR-6, IR-8 | Art.21(2)(b), Art.23 reporting |
| Art.13(8) — Declared support period ≥ 5 years | A.5.30 | PR.IP-9 | SA-3 | (no direct parallel) |
| Art.13(10) — User information | A.5.30, A.7.2.2 | PR.AT-1 | PL-4, AT-2 | (no direct parallel) |
| Art.13(14) — End-of-support notification (12 months prior) | A.8.32 | PR.IP-10 | SA-22 | (no direct parallel) |

### CRA Article 14 — Incident reporting

| CRA control | ISO 27001:2022 | NIST CSF 2.0 | NIST 800-53 Rev 5 | NIS2 | DORA |
|---|---|---|---|---|---|
| Art.14(2)(a) — 24h early warning to ENISA | A.5.24, A.5.25 | RS.CO-2 | IR-6, IR-6(1), IR-8 | **Art.23(4)(a)** — 24h early warning | **Art.19(4)(a)** — 24h initial |
| Art.14(2)(b) — 72h vulnerability notification | A.5.24, A.5.25 | RS.AN-1, RS.CO-2 | IR-6(1), IR-8 | **Art.23(4)(b)** — 72h notification | **Art.19(4)(b)** — 72h intermediate |
| Art.14(2)(c) — 14-day final vuln report | A.5.27 | RS.IM-1, RS.IM-2 | IR-4(3), IR-8 | Art.23(4)(c) final | Art.19(4)(c) final |
| Art.14(3) — Severe incident 24h/72h/1 month cascade | A.5.24 | RS.CO-2 | IR-6, IR-8 | **Art.23 same cascade** | Art.19 same cascade |
| Art.14(8) — Inform affected users | A.5.24, A.5.27 | RS.CO-4 | IR-6, IR-8 | Art.23(2) | Art.19(3) |

**The Article 14 cascade is the most-overlapping CRA element.** A single 24h/72h/14d reporting infrastructure can satisfy CRA + NIS2 + DORA simultaneously if scoped correctly. Reuse strongly recommended.

### CRA Article 18-20 — Supply-chain liability

| CRA control | ISO 27001:2022 | NIST CSF 2.0 | NIST 800-53 Rev 5 |
|---|---|---|---|
| Art.18 — Authorised representative obligations | A.5.20 (supplier agreements) | GV.OC-2 | SA-9, SR-2 |
| Art.19 — Importer verification + due diligence | A.5.19, A.5.20 | ID.SC-4 | SR-3, SR-6 |
| Art.20 — Distributor verification | A.5.19 | ID.SC-3 | SR-3, SR-11 |
| Art.21 — Rebrand / modification = manufacturer escalation | A.8.31 (change mgmt) | GV.RM-1 | CM-3, SA-10 |
| Art.24 — OSS steward obligations | A.5.20 (third-party agreements) | ID.SC-2 | SA-8(13), SR-3 |

### CRA Annex IV — Declaration of Conformity content

Annex IV content has no direct framework analogue — it's a CRA-specific document format. The closest reuse is **technical documentation processes** already in place for CE marking under the Low Voltage Directive (LVD), EMC Directive, or Radio Equipment Directive (RED) for connected radio products. Manufacturers familiar with those declarations can re-use their internal sign-off workflows.

### How to read this mapping operationally

- **If a row maps to a control you already implement under another framework**, your evidence collection is reusable. Configure the input to the CRA framework with the same fact and CRA reports compliant on that control.
- **If a row maps to multiple frameworks** (e.g. the Article 14 cascade), invest in ONE reporting infrastructure that satisfies all — don't build three.
- **If the right-hand columns are empty / "no direct parallel"**, the CRA obligation is genuinely CRA-specific. Examples: 5-year support period (Art.13(8)), end-of-support 12-month notification (Art.13(14)), explicit CRA citation in Declaration of Conformity (Annex IV.6). Budget for these as new work.

The evidence-bridge modules (`cra.supply_chain_evidence` and `cra.crypto_evidence`) automate the "reuse the same input" pattern for two of the highest-overlap areas — SBOM/signing/CVE and cryptography. Future evidence bridges (e.g. `cra.iam_evidence` consuming NIST 800-53 IA family) follow the same pattern.

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
| v0.4 | 2026-06-26 | Added Business case, "What it identifies" risk-category framing, Penalty exposure table with Tier 1/2/3 fines, Worked operational scenarios A–E, explicit "what the framework does NOT do" scoping |
| v0.5 | 2026-06-26 | Added evidence-bridge modules (`cra.supply_chain_evidence` re-uses SLSA findings → 14 CRA citations; `cra.crypto_evidence` re-uses ISO 27001 A.10 findings → 13 CRA citations); Cross-framework mapping section (ISO 27001 / NIST CSF 2.0 / NIST 800-53 / NIS2 / DORA per CRA Annex + Article); cleaned up misleading CRA mention in `digital_sovereignty/cyber_resilience_sovereignty.rego` header |

This document tracks the current state of the framework. When the CRA gets implementing acts (delegated regulations under Art.6, Art.27, Art.39), or when standardisation bodies publish harmonised standards under Art.27, those will land as additional rules in the relevant modules and trigger version bumps here.
