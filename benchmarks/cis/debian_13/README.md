# CIS Debian Linux 13 Benchmark v1.1.1

All 350 recommendations of the benchmark (333 Automated, 17 Manual), generated from the
benchmark's workbook by `tools/cis_generators/gen_debian_13.py`. Do not edit the `.rego`
files by hand: change the generator and regenerate.

| | |
|---|---|
| Framework key | `cis_debian_13` |
| Entrypoint | `data.cis_debian_13.main.compliance_report` |
| Roll-up | `data.cis_debian_13` (controls table, profile selector, section results) |
| Sections | 21 packages, `cis_debian_13.<section>` (filesystem, package_management, apparmor, ... user_group) |
| Profiles | `input.profile`: `level1_server` (default, 274), `level2_server` (350), `level1_workstation` (265), `level2_workstation` (347) |

## How a recommendation is decided

- Automated: from collected facts. Facts that were not collected give
  `<id>: evidence missing — <field> not collected`, never a pass.
- Manual: an attestation boolean, `input.attest.<name>`. Not attested is a violation.
- An empty input fails closed: `compliant` is false and `failed_controls` equals `total_controls`.

Recommendation ids, Automated/Manual status and profiles come from the workbook. The wording
of every message is ours; the benchmark's text is not reproduced here.

## Input

The fact contract is the one `benchmarks/cis/ubuntu_26_04/` reads, path for path, so one
collector feeds both modules. This release of the Debian benchmark numbers and scopes its
recommendations the same way as Ubuntu 26.04 LTS v1.0.0; the logic differs in two places:

- 6.2.3.2 requires an audit rule covering `execve` and `execveat`, for both `arch=b32` and `arch=b64`.
- 1.6.1 to 1.6.5 reject banner text that names the os-release ID, `debian`.

The audit-rule checks (6.2.3) need both `auditd.rules` (the lines of /etc/audit/rules.d/*.rules) and
`auditd.active_rules` (`auditctl -l`), collected separately: each rule is required in both.

The report also carries `violation_count`.

## Regenerate

```bash
python3 tools/cis_generators/gen_debian_13.py CIS_Debian_Linux_13_Benchmark_v1.1.1.xlsx
opa test benchmarks/cis/debian_13
```

Needs `openpyxl` and `opa` on the PATH. The workbook is CIS-licensed and is not committed.
The run aborts on any count, id, status, profile or title-keyword mismatch with the workbook.

`benchmarks/cis/debian_11/` is a separate, older module and is not replaced by this one.
