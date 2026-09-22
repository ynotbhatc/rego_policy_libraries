---
name: code-review
description: Pre-merge review of Rego policy changes (current branch diff or a PR number) against this library's recurring failure classes. Run it BEFORE opening or admin-merging a PR to catch what post-merge Copilot review otherwise finds — fail-open defaults, future/expired timestamp bypasses, malformed-data fail-open, hardcoded IDs, the data-subtree self-reference recursion trap, non-2-arg array.concat, undefined-field collapse, and vendor-neutrality leaks. Runs opa check/fmt/test on the changed policies and reports findings ranked by severity with a GO / HOLD verdict.
allowed-tools: Bash(git *) Bash(gh *) Bash(opa *)
---

Review the policy change **before** it merges. This library is a fail-closed
safety control: a policy that lets an ambiguous or malformed input take the
permissive path is a bug, not a nuance. The goal is to catch, pre-merge, the
exact defect classes that have repeatedly reached post-merge review here.
Produce a ranked findings list and a **GO / HOLD** verdict.

## 1. Get the diff and the changed policies

```bash
git fetch origin --quiet
git diff --stat origin/main...HEAD          # current branch vs main
git diff origin/main...HEAD                  # …or: gh pr diff <N>
# the changed .rego files:
git diff --name-only origin/main...HEAD | grep '\.rego$'
```

## 2. Compile + test the changed policies first (cheapest, catches the most)

```bash
opa check .                                  # whole library still compiles
opa fmt --diff <changed files>               # must be empty
opa test . --ignore .github                  # all tests pass
# For every changed policy with a compliance_report / decision entrypoint,
# eval with EMPTY input — it MUST return a populated fail-closed object,
# never {} and never undefined:
opa eval -d <dir> -f pretty 'data.<pkg>.compliance_report'
```

A policy that returns `{}` or `undefined` on empty input is the #1 silent
failure in this repo — the OPA endpoint then stores an empty result while the
job looks green. Treat it as a HOLD.

Also run the **`regal-lint`** skill on the changed files — it catches the
idiom/bug classes (unused vars, rule/builtin shadowing, unsafe comparisons,
fail-open `default` misuse) that `opa test` and `opa fmt` miss.

## 3. Dispatch reviewers (parallel), scoped to the diff

Spawn these in one message so they run concurrently, each told which files
changed. Relay only what survives verification; don't paste raw dumps.

- `pr-review-toolkit:silent-failure-hunter` — fail-open paths, defaults that
  wave through malformed input, missing `default … := false`.
- `compound-engineering:ce-correctness-reviewer` — logic, edge cases, the data-
  shape and recursion traps below.
- `compound-engineering:ce-security-reviewer` — for governance/enforcement
  policies: bypasses, identity spoofing, time-box evasion.

## 4. Repo-specific checklist (the recurring failures — check every one)

**Fail-open vs fail-closed — the cardinal sin here**
- Every rule that gates a decision has `default <rule> := false` (or the
  deny-by-default equivalent). A rule that never fires is `undefined`, not
  `false`. A control whose job is to *withhold* must escalate an unknown input,
  never proceed.
- **Malformed data must deny, not wave through.** If `input`/`data` is the wrong
  shape (missing key, wrong type, empty registry), the rule must fail closed.
  Guard the shape explicitly; don't let a missing field make a permissive path
  fire. (This is the "malformed agent registry fails open" class.)
- **Empty-input fail-closed** (see §2): bare `opa eval` with `{}` returns a
  populated non-compliant report, not `{}`.

**Undefined-field collapse**
- One `undefined` field inside an object literal turns the WHOLE object into
  `undefined` → the endpoint returns `{}`. Source every field of a
  `compliance_report`/`decision` object through a **defaulted** helper so a
  single missing fact can't collapse the report.

**The data-subtree self-reference recursion trap**
- Referencing a parent data subtree that contains the current package —
  e.g. `object.get(data.aac.ami, "meters", {})` from inside `package aac.ami.gate`
  — is a `rego_recursion_error` (the package depends on a tree that contains
  itself). Reference the **leaf document directly with a default** instead:
  `default _reg := {}` / `_reg := data.aac.ami.meters`. Also fails the OPA PUT
  with a 400.

**Time / approval logic** (the class Copilot just flagged)
- Timestamp checks reject **future** values — `now < start` and future-dated
  approvals must not pass an emergency/time-box gate.
- Approvals enforce **expiry** — a past-validity approval must be rejected by an
  explicit expiry comparison, not implicitly accepted.

**Hardcoded identifiers**
- No hardcoded AAP template/resource IDs as the primary key of a decision — IDs
  drift on re-seed / re-provision (the standing "launch by name, not id" lesson).
  Key on a stable name or a name-fragment; keep any id list as belt-and-braces,
  data-driven, and documented as regenerable.

**Rego v1 mechanics**
- `import rego.v1` at top; `if` on rule heads; `contains` for partial sets;
  `some x in y` for iteration.
- `array.concat` takes **exactly 2** arrays — nest for 3+.
- Sets and arrays are not interchangeable — `[v | some v in set]` before
  indexing/concat.

**Violation messages carry evidence**
- Each violation message includes the control id + a short description + the
  specific failure detail. Auditors read these, not the source. No generic
  "compliance check failed".

**Master orchestrator wiring**
- A new section/module is wired into the master's `violations` aggregation
  (remember the 2-arg `array.concat` rule) — an unaggregated section silently
  scores nothing.

**Input contract**
- The policy documents its input shape in a header comment, and the change
  doesn't silently break an existing consumer's shape (Ansible facts, the
  aac.m365 collection, AAP extracts, the portal ingestion pipeline).

**Vendor-neutrality / hygiene**
- No lab IPs (`192.168.4.62` / `192.168.4.26`) in policies, tests, or
  `sample_*_facts.json` fixtures — use `192.0.2.x` (RFC 5737) or `localhost`.
- No customer names or environment specifics in the shared library.
- Protected path: `enforcement/git/` changes need the
  `Approved-By: ynotbha@aisle-five.com` commit trailer.

## 5. Verdict

Rank surviving findings by severity (security/correctness first). Then:

- **HOLD** if any confirmed: fail-open on a safety control, malformed-data
  fail-open, empty-input `{}` collapse, undefined-field collapse, recursion
  error, future/expired-timestamp bypass, failing `opa test`, or missing
  Approved-By on `enforcement/git/`.
- **GO** otherwise — with residual nits listed for the author.

Fix HOLD findings before opening/merging; that is the whole point of running this
pre-merge.
