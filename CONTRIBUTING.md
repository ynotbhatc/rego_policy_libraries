# Contributing to Rego Policy Libraries

Thank you for contributing! This library grows by community submissions. Whether you're adding a new framework, extending coverage of an existing one, or fixing a bug — contributions are welcome.

---

## Three rules CI enforces

1. **Rego v1 only.** Every file carries `import rego.v1` and passes `opa check --strict`.
2. **Fail closed.** A framework given no facts, or facts it cannot interpret, reports `compliant: false` with an
   explicit `FAIL-CLOSED` reason. Silence is never a pass; a lack of facts is non-compliance.
3. **Metadata is the source of the documentation.** The `# METADATA` block on every package feeds the counts,
   the coverage scan and the OSCAL catalogs, profiles and component definition under
   [`converters/exports/oscal/`](converters/exports/oscal/), all derived from OPA's parse of the policy tree and
   validated against the OSCAL 1.2.3 schemas on every merge. A file without the block, or with values outside
   `scripts/metadata_vocabulary.json`, fails `make metadata`.

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

---

## Pull request checklist

- [ ] `# METADATA` block present on every new package and `make metadata` passes
- [ ] `import rego.v1` present in every new `.rego` file
- [ ] `default compliant := false` present
- [ ] `compliance_report` rule exported
- [ ] Violation messages include a control identifier
- [ ] Tests added for new controls (or existing tests still pass)
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
