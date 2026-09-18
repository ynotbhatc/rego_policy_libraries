# Coverage Roadmap — Frameworks, SaaS, Databases & Storage

A ranked backlog of well-known **frameworks**, **SaaS benchmarks**, and **database /
storage benchmarks** not yet in the library, to be added on a **cadence of one per week**
drawn from the combined backlog below (reorder by the deals in front of us). Gaps were
identified 2026-09-18 by enumerating the tree and verifying absence (`grep -rilE` returned
0 files for each). The library is already one of the broadest Rego policy sets available;
these are the conspicuous holes.

## Cadence and definition of done

One framework per week. A framework is **done** when it ships:

1. A module (or module set) under the right parent, package `<framework>.main`, exposing
   `compliance_report` — **fail-closed** (a framework given no facts reports non-compliant
   with an explicit reason, never a silent pass; `default … := false`).
2. Each control/safeguard as a violation rule with the **official identifier** in the
   message, tiered where the framework defines tiers (IG, maturity level).
3. `opa test` coverage — one case per rule (fires it) + a compliant case + a
   populated-report-on-empty-input case.
4. **Consumer wiring** in the compliance repo: the framework key in `opa_framework_map`
   (site_config.yml) so a playbook can route to it, plus any crosswalk overlay.
5. Count refreshed (`COVERAGE.md`, README headline) and a CHANGELOG entry.

Placement is decided per framework (existing parents: `federal`, `financial`,
`management`, `privacy`, `compliance`, `critical_infrastructure`, `regulatory`,
`sovereignty`). Regional government frameworks may warrant a new `regional/` parent.

## Track A — Compliance frameworks

| # | Target week | Framework | Why it's an obvious gap | Proposed home |
|---|---|---|---|---|
| **1** | **2026-09-18** | **CIS Controls v8** — the 18 Critical Security Controls / 153 safeguards, IG1–IG3 | Enormous CIS **Benchmark** depth but not the CIS **Controls** framework; the two are constantly conflated | `frameworks/management/cis_controls_v8/` |
| 2 | 2026-09-25 | **Zero Trust** — NIST SP 800-207 + CISA Zero Trust Maturity Model | Most-requested current architecture framework; pairs with existing NIST content | `frameworks/federal/zero_trust/` |
| 3 | 2026-10-02 | **Australia Essential Eight (ACSC)** — 8 strategies × maturity 0–3 | The single most-requested APAC framework; nothing substitutes | `frameworks/regional/essential_eight/` |
| 4 | 2026-10-09 | **CJIS Security Policy** | US state/local justice staple; FedRAMP/FISMA present but not this | `frameworks/federal/cjis/` |
| 5 | 2026-10-16 | **IRS Publication 1075 (FTI)** | Required for anyone handling Federal Tax Information | `frameworks/federal/irs_1075/` |
| 6 | 2026-10-23 | **UK Cyber Essentials** (+ Plus) | Common UK baseline; NCSC CAF present but distinct | `frameworks/regional/cyber_essentials/` |
| 7 | 2026-10-30 | **Germany BSI C5** | EU/DE sovereign-cloud attestation; sovereignty dir is generic | `frameworks/regional/bsi_c5/` |
| 8 | 2026-11-06 | **StateRAMP / TX-RAMP** | US state-gov cloud; FedRAMP present, state variants not | `frameworks/federal/stateramp/` |
| 9 | 2026-11-13 | **Regional gov-cloud pack** — Japan ISMAP · Australia IRAP/ISM · Singapore MAS TRM | Regional government/finance clouds; add as demand appears | `frameworks/regional/` |

## Track B — SaaS service benchmarks

Present today: **Microsoft 365 only** (CIS M365 + CISA SCuBA M365). Everything else is a gap.

| # | SaaS target | Why | Proposed home |
|---|---|---|---|
| B1 | **CISA SCuBA Google Workspace** (ScubaGoggles baselines) | Direct parallel to the SCuBA M365 suite we already ship — the strongest SaaS add | `benchmarks/scuba/gws/` |
| B2 | **CIS Google Workspace Foundations Benchmark** | The CIS peer to CIS M365, which we have | `benchmarks/cis/saas/google_workspace/` |
| B3 | **Snowflake** (CIS Snowflake Benchmark) | High-value data-platform SaaS; also closes a DB gap (Track C) | `benchmarks/cis/saas/snowflake/` |
| B4 | **Salesforce** (CIS / Security Health Check baseline) | Ubiquitous SaaS of record | `benchmarks/cis/saas/salesforce/` |
| B5 | **Okta / identity SaaS** | Identity is the SaaS control plane | `benchmarks/cis/saas/okta/` |
| B6 | **GitHub / GitLab org security** (CIS Software Supply Chain) | Source-of-truth SaaS; ties to the enforcement/supply_chain work | `benchmarks/cis/saas/github/` |
| B7 | Zoom · Atlassian (Jira/Confluence) · ServiceNow · Databricks | Add as demand appears | `benchmarks/cis/saas/<svc>/` |

## Track C — Database & storage benchmarks

Present today: **MySQL, Oracle, PostgreSQL** (CIS) + **MS SQL 2016, PostgreSQL 16** (STIG).
Thin — several mainstream engines missing, and **no dedicated storage benchmarks at all**.

| # | Target | Why | Proposed home |
|---|---|---|---|
| C1 | **MongoDB** (CIS MongoDB Benchmark) | The most-deployed NoSQL engine; absent | `benchmarks/cis/databases/mongodb/` |
| C2 | **Microsoft SQL Server** (CIS — we only have the STIG) | CIS SQL Server complements the existing STIG | `benchmarks/cis/databases/sql_server/` |
| C3 | **MariaDB** (CIS MariaDB Benchmark) | Widespread MySQL fork with its own benchmark | `benchmarks/cis/databases/mariadb/` |
| C4 | **Redis** hardening | Ubiquitous cache/store, commonly misconfigured | `benchmarks/cis/databases/redis/` |
| C5 | **Elasticsearch / OpenSearch** | Log & search backbone; security often neglected | `benchmarks/cis/databases/elasticsearch/` |
| C6 | **Storage infrastructure — NIST SP 800-209** | The authoritative storage-security standard; nothing covers it | `frameworks/federal/nist_800_209/` |
| C7 | **Object-storage hardening** (S3-compatible / MinIO / Ceph) | Generic object-store controls beyond the CIS AWS S3 checks | `benchmarks/storage/object_storage/` |
| C8 | Cassandra · IBM Db2 (expand) · CockroachDB · NetApp ONTAP | Add as demand appears | `benchmarks/cis/databases/<engine>/` |

## Notes

- **HITECH** is already covered (folded into the HIPAA module) — not on this list.
- Items 6–9 are lower-priority and market-dependent; reorder by the deals in front of us.
- Each addition is a self-contained PR (policies + tests), mergeable independently, so the
  cadence can slip a week without blocking anything else.
