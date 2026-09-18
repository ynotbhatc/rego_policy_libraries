# Regal on a large production Rego policy library — feedback

**Version:** v1.0 — 2026-09-18
**Author:** Tim Coulter, with Claude (Anthropic)
**For:** the Regal maintainers (`open-policy-agent/regal`)
**Also serves as:** the rationale for this repo's [`.regal/config.yaml`](../.regal/config.yaml).

Regal is a genuinely useful tool and now part of this repo's workflow (a committed
`.regal/config.yaml` plus a lint skill). This writeup is constructive feedback from
running it across a large, real-world policy library, in case it's useful for tuning the
default experience.

## Setup

| | |
|---|---|
| Tool | **Regal 0.36.1** (Go 1.25.1, darwin/arm64) |
| Target | `rego_policy_libraries` — **619 policy files, 758 `.rego` files** (incl. tests), 55+ compliance frameworks |
| Command | `regal lint .` with **default** configuration |
| OPA | 1.8.0 |

## Raw result

**8,229 violations, every one at level `error`.**

| Count | Rule |
|---|---|
| 2,920 | `style/line-length` |
| 984 | `style/prefer-some-in-iteration` |
| 760 | `style/messy-rule` |
| 696 | `idiomatic/directory-package-mismatch` |
| 488 | `style/opa-fmt` |
| 383 | `imports/unresolved-reference` |
| 330 | `style/rule-name-repeats-package` |
| 305 | `style/default-over-else` |
| 198 | `imports/pointless-import` |
| 154 | `bugs/redundant-existence-check` |
| 140 | `testing/file-missing-test-suffix` |
| 105 | `style/trailing-default-rule` |
| 67 | `style/unconditional-assignment` |
| 65 | `style/comprehension-term-assignment` |
| 64 | `style/avoid-get-and-list-prefix` |
| 61 | `idiomatic/equals-pattern-matching` |
| 47 | `style/pointless-reassignment` |
| 43 | `performance/defer-assignment` |
| 41 | `bugs/redundant-loop-count` |
| 41 | `bugs/leaked-internal-reference` |

## The actionable feedback — where defaults fight legitimate conventions

### 1. Test-context detection misses the `tests/test_*.rego` convention (highest-value fix)

OPA discovers tests by the `test_` **rule** prefix, not the filename — so a large body of
real-world libraries put tests in `tests/test_<name>.rego` rather than `<name>_test.rego`.
Regal only treats `*_test.rego` as a test context, which produces a **double
false-positive** on the same files:

- `testing/file-missing-test-suffix` fires on every test file (**140** here), and
- `performance/with-outside-test-context` **mis-fires** — it flags `with` used in test
  *helper* rules as a production-code performance issue, purely because the file isn't
  recognized as a test at all.

Recognizing any of **`test_*.rego`**, **files inside a `tests/` directory**, or **files
whose package name ends in `_test`** as a test context would eliminate both. This is the
single change that would most improve the out-of-box experience for policy libraries.

### 2. `idiomatic/directory-package-mismatch` (696) assumes directory == package

Policy libraries very commonly name packages by **framework/subject**
(`package cis_rhel9.selinux` living in `benchmarks/cis/rhel_9/`) because the package path
*is* the public query contract (`data.cis_rhel9.selinux...`), deliberately decoupled from
the file tree. For this whole class of project the rule is almost always a false positive.
Consider making it opt-in, or configurable to a root package prefix rather than a strict
path match.

### 3. `style/rule-name-repeats-package` (330) fires on the same deliberate naming

Section rules intentionally echo their framework package (`cis_rhel9.selinux` →
`selinux_*` rules). Heavy false-positive volume on an intentional convention.

### 4. `style/line-length` default (120) is aggressive for compliance content

2,920 hits, mostly long **auditor-facing violation messages** that intentionally quote
full control text. A higher default, or a message-string exemption, would fit this domain
better.

### 5. Everything defaults to `level: error`

An 8,000-error first run reads as "this repo is broken" and discourages adoption. A
**style-as-warning** default posture (errors reserved for `bugs/*`) would let genuine
defects stand out immediately on first contact.

## What worked — the real value

Silencing the four convention-driven rules above and raising `line-length` dropped the
count to **~4,300** and surfaced exactly the signal Regal is good at:

- `bugs/redundant-existence-check` (154)
- `bugs/redundant-loop-count` (41)
- `bugs/leaked-internal-reference` (41)
- `performance/defer-assignment` (43)

After calibration it became a keeper — the `bugs/*` and `performance/*` rules are the
strength. The only friction is a handful of convention-opinionated `style`/`idiomatic`
defaults that don't fit large policy libraries out of the box.

## This repo's calibration (for reference)

`.regal/config.yaml` sets `level: ignore` on `directory-package-mismatch`,
`rule-name-repeats-package`, and `testing/file-missing-test-suffix`; raises
`line-length` to 200; and scopes `performance/with-outside-test-context` out of
`**/tests/**` — while keeping every `bugs/*` and `performance/*` rule at full strength.

Thanks for building Regal — this feedback is offered in the spirit of making a good tool
fit large policy libraries with zero config.
