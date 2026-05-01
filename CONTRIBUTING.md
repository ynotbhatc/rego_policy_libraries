# Contributing to Rego Policy Libraries

Thank you for contributing! This library grows by community submissions. Whether you're adding a new framework, extending coverage of an existing one, or fixing a bug — contributions are welcome.

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

- [ ] `import rego.v1` present in every new `.rego` file
- [ ] `default compliant := false` present
- [ ] `compliance_report` rule exported
- [ ] Violation messages include a control identifier
- [ ] Tests added for new controls (or existing tests still pass)
- [ ] PR title follows the pattern: `feat(<framework>): add <description>` or `fix(<framework>): <description>`

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

## Requesting a framework

Open an issue using the **"Framework request"** template. Include:
- Framework name and version (e.g., "CIS Amazon Linux 2023 v1.0.0")
- Link to the source document (public PDF or webpage)
- Your use case (optional but helps prioritize)

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
