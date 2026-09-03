# The Control-Correlation Pattern

**Version:** v1.0
**Date:** 2026-09-03
**Authors:** Tim Coulter (Red Hat) with Claude (Anthropic)
**Status:** Pattern documented + first implementation shipped (`crosswalk/`)

> A pattern found should be expressed and documented, so we can align to it.
> This is that write-up: what the overlap between standards actually is, why
> it is a liability today, and the join that turns it into leverage.

## 1. The question

Once the STIG library reached 15 platforms beside the CIS benchmarks and the
regulatory frameworks, the load-bearing question became: **how much do these
standards overlap, and do they follow a consistent pattern across platforms —
or different ones?** The answer decides whether the library is N independent
silos or one system with N views.

## 2. What was measured

Two objective sources, no estimation:

- **CCIs** (Control Correlation Identifiers) embedded in every DISA STIG
  rule's XCCDF (`<ident system="…/cci">`), from the **July 2026 SRG-STIG
  Library Compilation**.
- **The DISA CCI List** (2025-01-23), which maps each CCI to a **NIST SP
  800-53** control.

Joining them gives, for every STIG rule across 15 platforms:
`stig_id → {CCI…} → {800-53 control…}`. CIS control coverage was swept by
benchmark section for the consistency comparison.

## 3. Finding 1 — the overlap is large, and it radiates from the OS

### Within a standard, across operating systems: near-total

STIG Linux family (RHEL 9, Ubuntu 22.04, SLES 15, Amazon Linux 2023), by
shared CCIs:

| Measure | Value |
|---|---|
| CCIs shared by **all four** OSes | 107 of 173 (61% of the union) |
| CCIs **unique to a single OS** | RHEL 9: 1 · Ubuntu: 1 · SLES: 4 · AL2023: 4 |

These are not four standards. They are **one requirement set re-instantiated
four times**, differing almost entirely in the *check command*, not the
*control*. CIS shows the same shape across its OS benchmarks (RHEL 9, RHEL 8,
Ubuntu, Rocky, Amazon Linux each land ~190–220 controls with a large shared
core).

### Across platform families: a gradient anchored on the OS

STIG cross-family CCI overlap (% of the smaller set shared):

| | Linux | Windows | Container | Database | Network |
|---|---|---|---|---|---|
| **Linux** | — | **91%** | 81% | 77% | 70% |
| **Windows** | 91% | — | 50% | 53% | 59% |
| **Container** | 81% | 50% | — | 65% | 43% |
| **Database** | 77% | 53% | 65% | — | 29% |
| **Network** | 70% | 59% | 29% | — | — |

Linux and Windows are 91% the same controls. Specialized platforms overlap
the OS spine heavily but each other lightly (network↔database: 29%).

### The whole corpus collapses onto a small control spine

**2,767 STIG rules across 15 platforms map onto just 65 distinct NIST 800-53
controls** — an average of **~43 rules per control**. Those 65 controls span
11 families (SC 16, AC 13, AU 10, IA 8, then CM/SI/MA/CA/RA/SA/CP). And there
is a **universal spine of 14 controls** present in ≥13 of the 15 platforms:

> AC-2, AC-3, AC-6, AC-17, AU-3, AU-4, AU-8, AU-9, AU-12, CM-5, CM-6, CM-7,
> IA-5, SC-28

account management, access enforcement, least privilege, remote access,
audit generation/capacity/timestamps/protection, config-change restriction,
least functionality, authenticator management, encryption at rest. **Every
platform re-expresses these same fourteen ideas.**

## 4. Finding 2 — the patterns are *inconsistent*, and that is the problem

The overlap above is invisible in the library as authored, because the
standards do not share a structure:

1. **Three unrelated ID schemes** — STIG `AZLX-23-000050` (SRG-derived), CIS
   `4.1.1.1` (benchmark section), NIST `AC-17` (control family). Nothing links
   them on the surface.
2. **Different wording for identical controls** — "Ensure SSH root login is
   disabled" (CIS) vs. "must not permit direct logons to the root account
   using remote access via SSH" (STIG). Text matching across the two returns
   near-zero; only a semantic or CCI join finds the equivalence.
3. **The cross-mappings were not preserved.** Standards *carry* the join key
   upstream (STIG XCCDF has a CCI on every rule) but the authored policy
   modules dropped it — so the same control was evaluated multiple times under
   multiple IDs with **no way to reconcile the results**.

The consequence: a Linux host was assessed for "encryption at rest" (SC-28) by
the STIG module, the CIS module, and nominally by a framework module — three
findings, one requirement, no join. Overlap without a join key is pure cost.

## 5. The pattern, stated

> **Standards are surface syntax over a shared control substrate. The
> substrate is NIST SP 800-53. Every standard should be joined to it, so a
> control is assessed once and reported against every standard that inherits
> it.**

The join key already exists for STIGs (CCI→800-53). CIS publishes a mapping to
CIS Controls v8, which maps to 800-53. Regulatory frameworks (PCI, ISO, NERC
CIP, HIPAA) publish 800-53 crosswalks. **800-53 is the natural spine** because
every other standard already defines its relationship to it.

## 6. The implementation (shipped)

`crosswalk/` in this library:

- **`crosswalk/stig_800_53/data.json`** — the measured `stig_id → [800-53]`
  map for all 15 platforms (2,767 rules), with provenance.
- **`crosswalk/correlation.rego`** (`package crosswalk.correlation`) — the
  "assess once, report many" engine. Given a platform's findings it produces
  `control_status[<800-53>] = satisfied | gap | (absent = not evaluated)` plus
  a family rollup. **Gap wins**: if any evaluated rule mapping to a control is
  Open, the control is a gap. **Unassessed controls are absent, never passed**
  — the same fail-closed honesty as the rest of the library.

Downstream, any framework that declares its 800-53 inheritance reads
`control_status` and reports its own posture from one assessment — the input
to the portal's technical-debt heat map and the audit-evidence story (one
finding, the list of frameworks it discharges).

## 7. Validating future patterns — how new standards align

This is the reusable part. When a new standard enters the library:

1. **Find its 800-53 relationship** (published crosswalk, CCI, or authored
   mapping) — do not invent a fourth ID island.
2. **Add its `<id> → 800-53` map** beside `stig_800_53/`, same shape.
3. **The overlap becomes measurable immediately** — run the same CCI/control
   set-analysis to see what the new standard shares with the spine and what is
   genuinely new. A standard that adds *zero* new 800-53 controls is a
   re-wording (report it via the existing spine, do not re-author checks); a
   standard that adds new controls tells you exactly where new assessment
   logic is actually needed.
4. **Consistency check**: a new OS benchmark that does not overlap the
   14-control spine by the expected ~90% is a signal — either the benchmark is
   unusual, or the mapping is wrong. The spine is now a validation oracle.

The measurement scripts live with `tools/stig_generators/` (CCI extraction +
crosswalk step); regenerate on each quarterly DISA release and re-diff against
this document's figures.

## 8. Figures to re-verify on regeneration

| Figure | Value (July 2026 library) |
|---|---|
| STIG platforms crosswalked | 15 |
| STIG rules mapped | 2,767 |
| Distinct 800-53 controls | 65 |
| 800-53 families touched | 11 |
| Universal spine (≥13/15 platforms) | 14 controls |
| Linux OS-family shared CCIs | 107 of 173 (61%) |
| Linux↔Windows control overlap | 91% |

Numbers drift with each quarterly release; the *pattern* does not.
