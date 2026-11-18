# How big is this library, measured?

**Other projects measured 2026-10-12; this library re-measured 2026-11-17 on `main` after v2.5.0.** Every number below for
another project was taken from that project's public repository on the first date (file counts by type), or from its
published figures where no repository is public, and has not been re-measured since. Ours is `make count`
(`scripts/count_controls.py`), which CI reruns on every merge and compares with the README and with the figures in
this page (the claim line and the table row).

## The claim, and what it rests on

> The largest open library of executable compliance policy anyone can verify, and the broadest regulatory
> coverage of any machine-readable policy library, open or closed.

- **"Largest open … anyone can verify"** rests on the control-level count: 29,347 checks across 1,052 policy files (counted by OPA's parser across every policy shape; earlier releases used a line-based counter and then a counter that read only one of six shapes, see CHANGELOG 2.3.0 and 2.3.1, so their figures are not comparable). What that number is and is not is set out under [What the count is](#what-the-count-is-and-is-not) below. The next
  largest public set is Azure Policy's built-in definitions (5,130), then ComplianceAsCode (2,574). Units differ
  slightly (one Azure definition is one resource-property check; one of our table rows is one attested control),
  which is why the claim says *verify*, not *by any measure*.
- **"Broadest regulatory coverage … open or closed"** rests on the framework list in the README: host benchmarks,
  cloud, SaaS, Kubernetes, IaC gating, AI governance, MCP, financial regulators on three continents, privacy law on
  four, critical infrastructure, sovereignty. Mapping products (SCF, the GRC platforms) map more frameworks but
  execute none of them; the executable libraries each cover one domain.
- **The library most often named as "the largest OPA Rego compliance library"** is Kubescape's regolibrary. Measured
  the same way on the same day it holds 304 Rego rules and 290 controls across 19 Kubernetes frameworks; it is
  excellent at what it does, in one domain, and about one percent of this library's count by the same counter.
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
| **Rego Policy Libraries** | one Rego policy file (one to a few hundred controls each) | **1,052 files, 29,347 control-level checks** | 190 framework catalogs, 130+ framework directories | yes, every domain above |
| trivy-checks (Aqua) | one Rego check | 563 | cloud, k8s, docker | yes |
| Kubescape regolibrary (ARMO) | one Rego rule (Kubernetes misconfiguration) | 304 rules, 290 controls | 19 frameworks, all Kubernetes (CIS K8s/EKS/AKS/GKE, NSA, MITRE, SOC 2) | yes, Kubernetes only |
| Kyverno policies | one admission policy | 180 | Kubernetes | yes |
| Gatekeeper library | one constraint template | 49 | Kubernetes | yes |

Not counted: Tenable, Qualys, CIS-CAT Pro, Wiz, Orca, and the GRC mapping platforms, because their rule sets are
closed or their "frameworks supported" are evidence mappings rather than executable checks.

## How the control count works

`scripts/count_controls.py` parses every non-test `.rego` file with OPA's own parser (`scripts/rego_ast.py`) and
counts, per file, the distinct (control id, message text) pairs it finds (in violation messages, `deny` / `warn` /
`finding` rule bodies, and the rows of `controls` / `items` / `standards` style tables) plus each violation rule or
check entry that carries no id. Tables that are not controls (sections, chapters, deadlines, report scaffolding) are excluded by name.
The total is the sum over files. See [What the count is, and is not](#what-the-count-is-and-is-not) below for what that
does and does not mean.

Reproduce it:

```
make count
```

CI runs the same script with `--check-readme` and fails the build if the README's number, or the figures in this page's claim line and table row, no longer match.

## What the count is, and is not

`29,347` is a **parser metric**, not a count of distinct controls in the standards. Per non-test file, the counter
adds the distinct (control id, message text) pairs it finds plus each violation rule or check entry that carries no
id, and then sums over files. Four consequences:

1. **One control can be several checks.** A control with two rules, or the same rule worded for a failing value and for
   missing evidence, contributes one per distinct message. The unit is the check, not the control.
2. **A recommendation cited by two modules is counted twice.** A section module and the roll-up or complete module
   that repeats it each contribute. The sum is not de-duplicated across files.
3. **Ids that are not recommendations are counted.** A table key, a report scaffold key or a cross-reference
   (a `NIST SC-28` or `STIG RHEL-09-...` tag on a CIS check) counts as a cited id when it sits in a shape the
   counter reads.
4. **Unlike things are summed.** One row of an attestation table, one violation rule and one benchmark
   recommendation each count as one.

Worked example, CIS Red Hat Enterprise Linux 9 v3.0.0 (`benchmarks/cis/rhel_9/`, recomputed 2026-11-17 with the
parser the counter uses):

| Figure | Value | What it is |
|---|---:|---|
| Per-file checks, summed over the 20 non-test files | 746 | what `count_controls.py` adds to the headline for this directory: distinct (id, message) pairs plus id-less checks |
| Distinct cited id strings in the directory | 377 | each id once, however many messages or modules cite it |
| Of those, numeric ids (`1.1.1.1` form) | 352 | the same number as the benchmark's 352 recommendations (`standard_total`) |
| Of those, other tokens | 25 | 16 CIS/NIST/STIG cross-reference tags on the STIG-extension modules, and 9 table or report keys the parser reads as ids |

So this directory adds 746 to the headline while the benchmark has 352 recommendations. The coverage stamp on
`cis_rhel9_main.rego` compares the distinct-id figure (377) with the declared 352, and calls the module `full`
because the ratio is above 0.9; it does not say the extra 25 are not recommendations.

**OSCAL controls.** The catalog exporter's `controls` total in `converters/exports/oscal/dist/catalogs/index.json` (22,455
at the last export) is also a different quantity: the exporter emits one OSCAL control per rule or message it finds in each
framework's modules, and that includes message templates. SAE AS9100D is the example its own module documents
(`frameworks/management/as9100d/as9100d_main.rego`): 71 clause rows are exported as 88 controls, because 17 template
controls (the "not attested" and `FAIL-CLOSED` message templates and the package's two contract rules) are counted as
controls of their own. The 190 catalogs are one per framework key, not one per standard.

**What to quote.** Use "29,347 control-level checks" only with its definition (per-file parser hits). For a number
that means "distinct requirements of a standard", take a module's declared `standard_total` where it has one
(352 for the RHEL 9 benchmark above), not the sum. The 90 % density rule in `scripts/coverage_stamp.py` only flags a
module whose cited ids fall below 90 % of its own declared total; a module can sit above that line and still be
short or long by a few. Windows Server 2019 is an example the other way: it declares 400, evaluates all 400
(398 from facts, 2 Manual by attestation) and the counter sees 399 distinct ids, because the two attestation
recommendations sit in a table shape the counter does not read as ids and one report key is read as an id.

The per-control result lists a report carries (`control_results`, with its static index of id, basis, profile and
evidence paths) are **not** counted: they restate controls already counted from their violation rules. The counter
skips them by rule name (`REPORTING` in `scripts/rego_ast.py`); adding them to eleven CIS modules left the total unchanged.

