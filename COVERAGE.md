# Test coverage

> **Generated** — do not edit by hand. Refresh with `python3 scripts/coverage_report.py > COVERAGE.md`

**760 of 770 policy files have tests (99%).** 794 test files, 10 policies still uncovered.

## Why this file exists

This library is maintained on a best-effort basis and it is free. Publishing
the gap is cheaper than hiding it, and it is the most honest answer to
"where can I help?" — every uncovered policy below is a real, bounded,
mergeable contribution.

**Each one is small.** Copy the shape of a test that already exists next to
a covered policy, write cases for the violations the policy defines, and run
`opa test`. It passes or it does not — there is no judgement call. See
[CONTRIBUTING.md](CONTRIBUTING.md).

Pick anything below, open a PR, and say in the description which file you
took so two people do not write the same test.

## Where the gaps are

| area | policies without tests |
|---|---|
| `benchmarks/stig` | 4 |
| `frameworks/federal` | 3 |
| `benchmarks/cis` | 1 |
| `frameworks/financial` | 1 |
| `frameworks/management` | 1 |

## The queue

<details><summary><code>benchmarks/cis/rhel_8</code> — 1 file(s)</summary>

- `cis_rhel8_complete.rego`

</details>

<details><summary><code>benchmarks/stig/oracle_linux_8</code> — 1 file(s)</summary>

- `stig_oracle_linux_8_complete.rego`

</details>

<details><summary><code>benchmarks/stig/oracle_linux_9</code> — 1 file(s)</summary>

- `stig_oracle_linux_9_complete.rego`

</details>

<details><summary><code>benchmarks/stig/rhel_8</code> — 1 file(s)</summary>

- `stig_rhel8_complete.rego`

</details>

<details><summary><code>benchmarks/stig/rhel_9</code> — 1 file(s)</summary>

- `stig_rhel9_complete.rego`

</details>

<details><summary><code>frameworks/federal/cmmc</code> — 1 file(s)</summary>

- `cmmc_main.rego`

</details>

<details><summary><code>frameworks/federal/fedramp</code> — 1 file(s)</summary>

- `fedramp_main.rego`

</details>

<details><summary><code>frameworks/federal/nist/ai_rmf</code> — 1 file(s)</summary>

- `nist_ai_rmf.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/security_testing</code> — 1 file(s)</summary>

- `requirement_11.rego`

</details>

<details><summary><code>frameworks/management/soc2</code> — 1 file(s)</summary>

- `soc2_assessment.rego`

</details>

