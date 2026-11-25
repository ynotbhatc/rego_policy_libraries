# Contributing to Rego Policy Libraries

Thank you for contributing! This library grows by community submissions. Whether you're adding a new framework, extending coverage of an existing one, or fixing a bug — contributions are welcome.

---

## Three rules CI enforces

1. **Rego v1 only.** Every file carries `import rego.v1` and passes `opa check --strict`.
   Every module must also compile **on its own**: the product uploads one file at a time into an empty OPA
   server, so a rule used by a module lives in that module (or in a package loaded before its directory),
   and an empty table is written `object.union({}, {})`, `set() | set()` or `array.concat([], [])`, never a
   literal `{}` / `set()` / `[]` that is later indexed or iterated (OPA >= 1.22 rejects that as an undefined
   ref). `make check-per-file-load` proves it (`OPA_IMAGE=docker.io/openpolicyagent/opa:latest` runs the
   server from the product's image with podman).
2. **Fail closed.** A framework given no facts, or facts it cannot interpret, reports `compliant: false` with an
   explicit `FAIL-CLOSED` reason. Silence is never a pass; a lack of facts is non-compliance.
3. **Metadata is the source of the documentation.** The `# METADATA` block on every package feeds the counts,
   the coverage scan and the OSCAL catalogs, profiles and component definition under
   [`converters/exports/oscal/`](converters/exports/oscal/), all derived from OPA's parse of the policy tree and
   validated against the OSCAL 1.2.3 schemas on every merge. A file without the block, or with values outside
   `scripts/metadata_vocabulary.json`, fails `make metadata`.
4. **No verbatim CIS benchmark text.** This repository is Apache-2.0. CIS benchmark
   recommendation titles, rationale, and remediation text are not reproduced.
   A check is cited by its control id plus a short original description of what
   the Rego evaluates (the pattern in `benchmarks/cis/saas/m365_v7/`). Do not
   paste the benchmark's "Ensure …" sentence into a message, a comment, a
   `title` field, a test, or a generator. `tools/cis_generators/neutralize.py`
   is what the generators use instead. `scripts/check_cis_verbatim.py` fails CI
   if that sentence shape shows up again under `benchmarks/cis/`.

---

## Quick contribution guide

### 1. Adding a new framework

**Taxonomy:** place your policy in the matching subdirectory:

| Type | Location |
|------|----------|
| CIS Benchmark | `benchmarks/cis/os/linux/`, `benchmarks/cis/cloud/`, etc. |
| DISA STIG | `benchmarks/stig/` |
| Federal (NIST, FISMA, FedRAMP, CMMC) | `frameworks/federal/` |
| Management (ISO, SOC 2, NCSC CAF) | `frameworks/management/` |
| Financial (PCI-DSS, SOX, SWIFT) | `frameworks/financial/` |
| Privacy (GDPR, HIPAA) | `frameworks/privacy/` |
| Critical infrastructure (NERC-CIP, IEC 62443) | `frameworks/critical_infrastructure/` |
| Regulatory (DORA, NIS2) | `frameworks/regulatory/` |
| Enforcement (Ansible, Terraform, K8s) | `enforcement/` |
| AI / Governance | `governance/` |

**Required structure:**

```rego
# METADATA
# title: "<Framework Name> — <section or control group>"
# custom:
#   class: compliance            # security | compliance | ot | governance | enforcement | threat-detection
#   framework: <framework_slug>  # e.g. cis_rhel_9, nist_sp_800_53, nerc_cip
#   source: <authority>          # from scripts/metadata_vocabulary.json
#   domains: [<tag>, <tag>]      # from scripts/metadata_vocabulary.json
package <framework>.<module_name>

import rego.v1

# ---------------------------------------------------------------------------
# <Framework Name> — <section or control group>
# Reference: <link to standard or source document>
# ---------------------------------------------------------------------------

default compliant := false

violations contains msg if {
    # condition
    msg := "<control-id>: <human-readable description of violation>"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "framework":      "<framework name>",
    "section":        "<section name>",
    "total_controls": <N>,
    "violations":     violations,
    "compliant":      compliant,
}
```

**Rules:**
- The `# METADATA` block is mandatory and checked by `make metadata` (`scripts/check_metadata.py`). Values for `source` and `domains` come from `scripts/metadata_vocabulary.json`; add new ones there in the same PR. One block per *package*: if your package already exists in another file, that file owns the block (see CLAUDE.md, *Skill: policy metadata*)
- `import rego.v1` is mandatory — no exceptions
- Every policy must export a `compliance_report` rule with at minimum: `compliant`, `violations`
- Violation messages must include a control identifier (e.g., `"CIS 1.1.1: ..."`, `"CIP-007 R2: ..."`)
- `default compliant := false` is required — without it, a rule that never fires is `undefined`, which breaks aggregation

### 2. Extending an existing framework

Open a PR against the specific `.rego` file. Include:
- Which control(s) you're adding or fixing
- A reference link to the source standard

### 3. Writing tests

OPA tests live alongside policies. Name your test file `<policy_name>_test.rego`:

```rego
package <framework>.<module_name>_test

import rego.v1

test_violation_fires_when_control_missing if {
    result := violations with input as {"some_fact": false}
    count(result) > 0
}

test_compliant_when_all_controls_pass if {
    result := compliant with input as {"some_fact": true, ...}
    result == true
}
```

Run tests locally:
```bash
opa test benchmarks/cis/os/linux/rhel_9/ -v
```

The CI pipeline (`.github/workflows/opa-test.yml`) runs all tests on every PR.

To check that the tests check something, run `make mutation MODULE=<dir>` (on demand, not in CI). It flips
comparisons and booleans, drops a `not` or a rule-body line, and lists every change the tests missed. Where the
standard's text may be reused (NIST SP 800-53, DISA STIG check text), add golden cases built from that text. Both
are described in [docs/testing/MUTATION_AND_GOLDEN.md](docs/testing/MUTATION_AND_GOLDEN.md).

Tests go in a test file (`tests/`, `test_*.rego` or `*_test.rego`) in a package of their own. A rule named
`test_*` in a policy file is run by `opa test` and published with the library; `make check-no-library-tests`
(part of `make check-coverage`) rejects it.

#### Bad input never passes (`make check-bad-input`)

`scripts/check_bad_input_fails.py` evaluates every `compliance_report` entrypoint on input that is empty, null
or wrongly typed, and on mutated copies of the module's own all-pass test fixtures (a boolean as `"true"`,
`"false"`, `"no"`, null or missing; a number as a string; a field dropped). A report that still passes is a
failure. The script's docstring is the full description; what a contributor needs:

- **Give the module an all-pass fixture.** Any object-valued rule in the module's tests on which the entrypoint
  reports a pass is found by evaluation. When a module has levels or profiles (CIS Level 1 and 2, FedRAMP
  Low / Moderate / High), write one all-pass object per level: up to four distinct fixtures are used. The
  largest is the primary; each further one gets cases for the facts it holds with a value the earlier ones do
  not, named `<case>@<rule name>`. Do not name an all-pass object `bad_*`, `missing_*`, `invalid_*` and the
  like; such names are read as failing cases.
- **A fixture should hold only facts its level reads.** When a mutated fact still passes, the check tries the
  same fact at an honestly bad value (the opposite boolean; a number at 0 and at plus or minus 10^9). If that
  passes too, the fixture does not depend on the fact. The case is then not counted when the module's own
  report shows the fact feeds advisory output only (`unscored`), or when another all-pass fixture depends on
  the fact and fails the mutation (`scoped`). Otherwise, on the primary fixture, it stays a failure and its
  detail says `inert`: add the fixture that reads the fact, or take the unread field out of the fixture. (On a
  further fixture the same finding is printed as `unread` and is not a failure.)
- **Two lists, never the same case in both.**
  [`scripts/bad_input_known_failures.txt`](scripts/bad_input_known_failures.txt) is generated
  (`--write-known`) and is the list to fix. [`scripts/bad_input_accepted.txt`](scripts/bad_input_accepted.txt)
  is written by hand and holds behaviour that was reviewed and is right, one
  `<package> <case>: <reason>` per line. The reason is mandatory and must say why: the rule id, audit
  procedure or collector contract that makes a string, a missing fact or an unscored fact correct ("by design"
  is refused). A family may be accepted with `*` in the case, and then the reason must cite a document (a URL
  or a file in this repository). An accepted entry whose case no longer fails, or no longer exists, fails the
  check, so the list cannot outlive what it describes. Check the file's form without running OPA with
  `python3 scripts/check_bad_input_fails.py --lint-accepted`.
- `--only <package> --verbose` prints, for one module, the fixtures used, every known entry that still fails,
  and every accepted and excused case with its reason.

---

## Pull request checklist

- [ ] `# METADATA` block present on every new package and `make metadata` passes
- [ ] `import rego.v1` present in every new `.rego` file
- [ ] `default compliant := false` present
- [ ] `compliance_report` rule exported
- [ ] Violation messages include a control identifier and original wording (no verbatim CIS benchmark text)
- [ ] Tests added for new controls (or existing tests still pass)
- [ ] `make check-per-file-load` passes (every module uploads on its own into an empty OPA server)
- [ ] `make check-bad-input` reports no new failure for the module (`--only <package> --verbose`); nothing was added to `scripts/bad_input_accepted.txt` without a reason that cites the rule or contract
- [ ] PR title follows the pattern: `feat(<framework>): add <description>` or `fix(<framework>): <description>`
- [ ] `make check-converters` passes (the OSCAL, SARIF and crosswalk exports rebuild and validate; commit the regenerated `dist/` files)

---

## array.concat() — the most common Rego v1 mistake

`array.concat()` takes **exactly 2 arrays**. For 3+ arrays, nest the calls:

```rego
# WRONG — 3-argument concat does not exist in Rego v1
all := array.concat([a], [b], [c])

# CORRECT — nested 2-argument calls
ab   := array.concat([a], [b])
all  := array.concat(ab, [c])
```

---

## Where help is wanted

The gap we are closing is breadth. [`docs/SCF_GAP.md`](docs/SCF_GAP.md) lists every document the Secure
Controls Framework maps, which ones this library covers, and the order we are working in; pick any row marked
`gap` or `partial`. Three kinds of help move it fastest:

- **A framework from its public text**, written the way the existing modules are (one control per obligation,
  the document's own identifiers, fail-closed, tested). The phase order in the gap document is a suggestion,
  not a queue.
- **Source documents we cannot fetch.** Some rows need a licensed or login-gated document (PCI DSS SAQs,
  CSA CCM 4.1.0, ISO/IEC 27701:2025, SWIFT CSCF). If you hold a licence that lets you contribute the control
  list, say so in the issue.
- **Collectors and mappings.** The library evaluates facts; it does not gather them. An Ansible or Graph API
  collector that produces the input a module declares (for example a Microsoft 365 tenant dump for the CIS
  M365 and SCuBA modules), or an authoritative crosswalk that maps a module's controls to NIST SP 800-53 at
  enhancement granularity, widens what the OSCAL baseline coverage can claim.

---

## Requesting a framework

Open an issue using the **"Framework request"** template. Include:
- Framework name and version (e.g., "CIS Amazon Linux 2023 v1.0.0")
- Link to the source document (public PDF or webpage)
- Your use case (optional but helps prioritize)

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
