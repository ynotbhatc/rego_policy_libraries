# Contributing to Rego Policy Libraries

Thank you for your interest in contributing! This guide covers conventions and
the review process so your PR is accepted quickly.

---

## Quick start

```bash
git clone https://github.com/ynotbhatc/rego_policy_libraries.git
cd rego_policy_libraries
# Install OPA v0.60+: https://www.openpolicyagent.org/docs/latest/#1-download-opa
make check   # syntax-check + fmt-check + tests
```

---

## Where to place new policies

Follow the three-axis taxonomy in the repository root:

| Domain | Path | Example |
|--------|------|---------|
| CIS Benchmarks / DISA STIGs | `benchmarks/cis/` or `benchmarks/stig/` | `benchmarks/cis/os/linux/rhel_9/` |
| Regulatory frameworks | `frameworks/<category>/<standard>/` | `frameworks/financial/pci_dss/` |
| Gate-style enforcement | `enforcement/<tool>/` | `enforcement/terraform/` |
| Operational governance | `governance/<area>/` | `governance/ai/` |
| Threat detection | `threat_detection/<category>/` | `threat_detection/crypto_mining/` |

---

## Rego style guide

1. **Rego v1 syntax only** — every file must begin with `import rego.v1`.
2. **Package names** must mirror the directory path, using underscores for path
   separators (e.g. `benchmarks/cis/os/linux/rhel_9/` → `package cis_rhel9.<module>`).
3. **Unique package names** — no two `.rego` files in the same OPA bundle may
   share the same package.  Prefer descriptive sub-packages over reusing names.
4. **`default` rules required** — any boolean helper rule that is referenced
   inside an object literal or in a cross-module import must have a
   `default <rule> := false` declaration so that the rule is never `undefined`.
5. **Expose a standard output rule** — compliance/assessment modules should
   expose one top-level report rule (e.g. `compliance_assessment` or
   `<standard>_compliance_report`) with at minimum:
   ```rego
   report := {
       "compliant": ...,
       "violations": [...],
   }
   ```
6. **No test code in production files** — place `test_*` rules in a dedicated
   `<module>_test.rego` file in the same directory.
7. **`opa fmt`** — run `make fmt` before committing so CI formatting checks pass.

---

## Adding tests

Every new or modified policy should include a `*_test.rego` companion file:

```
benchmarks/cis/os/linux/rhel_9/
    pam_validation.rego
    pam_validation_test.rego   ← new
```

Run tests locally:

```bash
make test
# or a specific directory:
opa test benchmarks/cis/os/linux/rhel_9/ -v
```

---

## Pull request checklist

- [ ] `make check` passes (fmt-check + lint + tests)
- [ ] New `.rego` files placed in the correct taxonomy directory
- [ ] `import rego.v1` present at the top of each file
- [ ] Package name is unique and mirrors the directory path
- [ ] Any boolean helper rules used in report objects have `default := false`
- [ ] A `*_test.rego` file accompanies new policy modules
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`

---

## Commit message format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add CIS RHEL 10 benchmark policies
fix: correct SSH MaxAuthTries threshold in rhel_9 PAM module
chore: pin OPA version to v0.70.0 in CI
docs: add examples for FedRAMP moderate input
```

---

## Reporting security issues

Please **do not** open a public issue for security vulnerabilities.
Email the maintainer directly (see the GitHub profile) with details.

---

## License

By contributing you agree that your contributions will be licensed under the
[Apache 2.0 License](LICENSE) that covers this project.
