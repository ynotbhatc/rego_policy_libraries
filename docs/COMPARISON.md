# How big is this library, honestly?

**Measured 2026-10-12 at v2.3.3.** Every number below for another project was taken from that project's public
repository on the same day (file counts by type), or from its published figures where no repository is public.
Ours is `make count` (`scripts/count_controls.py`), which CI reruns on every merge and compares with the README.

## The claim, and what it rests on

> The largest open library of executable compliance policy anyone can verify, and the broadest regulatory
> coverage of any machine-readable policy library, open or closed.

- **"Largest open … anyone can verify"** rests on the control-level count: 13,758 checks at v2.3.3 (counted by OPA's parser across every policy shape; 2.2.0's 7,867 came from a line-based counter and 2.3.0's 7,560 read only one of six shapes — see CHANGELOG 2.3.0 and 2.3.1). The next
  largest public set is Azure Policy's built-in definitions (5,130), then ComplianceAsCode (2,574). Units differ
  slightly (one Azure definition is one resource-property check; one of our table rows is one attested control),
  which is why the claim says *verify*, not *by any measure*.
- **"Broadest regulatory coverage … open or closed"** rests on the framework list in the README: host benchmarks,
  cloud, SaaS, Kubernetes, IaC gating, AI governance, MCP, financial regulators on three continents, privacy law on
  four, critical infrastructure, sovereignty. Mapping products (SCF, the GRC platforms) map more frameworks but
  execute none of them; the executable libraries each cover one domain.
- **The library most often named as "the largest OPA Rego compliance library"** is Kubescape's regolibrary. Measured
  the same way on the same day it holds 304 Rego rules and 290 controls across 19 Kubernetes frameworks; it is
  excellent at what it does and one-twentieth of this library's size, in one domain.
- **What we do not claim:** largest in the world by rule count. The closed libraries (CIS-CAT's XCCDF set, Tenable
  audit files, Qualys Policy Compliance) cover hundreds of benchmarks as per-setting checks and are probably larger.
  They publish no auditable count, so neither side can prove it, and we do not try.

## The numbers

| Library | What a "rule" is | Rules | Frameworks / profiles | Executable? |
|---|---|---|---|---|
| Azure Policy built-ins (Microsoft) | one resource-property check | 5,130 definitions | 267 initiatives | yes, Azure only |
| ComplianceAsCode / SCAP Security Guide | one OS setting | 2,574 rules | 391 profiles, 39 products | yes, OS only |
| KICS (Checkmarx) | one IaC query | 1,813 | 22+ IaC platforms | yes, IaC only |
| Prowler | one cloud API check | 1,625 | 112 mapping files | yes, cloud only |
| Secure Controls Framework 2026.3 | one catalogue control | 1,591 | 270 mapping columns, 234 distinct documents ([gap plan](SCF_GAP.md)) | **no** (Excel / JSON / OSCAL) |
| Steampipe AWS compliance mod | one SQL control | 1,361 | ~17 benchmarks | yes, AWS only |
| Checkov | one IaC policy | ~1,000+ (vendor figure) | IaC | yes, IaC only |
| **Rego Policy Libraries** | one Rego policy file (one to a few hundred controls each) | **770 files, 14,318 control-level checks** | 54 tracked standards, 130+ framework directories | yes, every domain above |
| trivy-checks (Aqua) | one Rego check | 563 | cloud, k8s, docker | yes |
| Kubescape regolibrary (ARMO) | one Rego rule (Kubernetes misconfiguration) | 304 rules, 290 controls | 19 frameworks, all Kubernetes (CIS K8s/EKS/AKS/GKE, NSA, MITRE, SOC 2) | yes, Kubernetes only |
| Kyverno policies | one admission policy | 180 | Kubernetes | yes |
| Gatekeeper library | one constraint template | 49 | Kubernetes | yes |

Not counted: Tenable, Qualys, CIS-CAT Pro, Wiz, Orca, and the GRC mapping platforms, because their rule sets are
closed or their "frameworks supported" are evidence mappings rather than executable checks.

## How the control count works

`scripts/count_controls.py` counts, in every non-test `.rego` file: `violation(s)|deny|warn|finding(s) contains … if`
rule bodies; rows of top-level tables whose values are objects (the `controls` / `items` / `standards` tables of the
attestation modules, one row per control); and rows of named check tables whose values are the violation message.
Tables that are not controls (sections, chapters, deadlines, report scaffolding) are excluded by name. A body that
iterates a table is counted once besides its rows, an over-count of one per table.

Reproduce it:

```
make count
```

CI runs the same script with `--check-readme` and fails the build if the README's number no longer matches.
