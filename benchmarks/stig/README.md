# DISA STIG Benchmarks

Per-platform STIG implementations. Every platform directory carries:

- domain/`core` modules with per-rule finding objects — `vuln_id`, `stig_id`,
  `severity` (CAT I/II/III), `rule_title`, `status` (`Not_a_Finding`/`Open`)
- a `stig_<platform>_complete.rego` master aggregator (`stig_assessment` +
  the library's uniform `compliance_report` contract)
- a `stig_<platform>_main.rego` framework-key alias with the **fail-closed
  empty-input gate**: no facts → fully non-compliant with an explicit
  finding, never a pass
- tests: empty-input smoke + green-fixture full-closure (+ alias fail-closed)

**Rule IDs are verified against the current DISA SRG-STIG Library
Compilation before stamping** (July 2026 library, verified 2026-09-03).
Coverage per platform is stated honestly in each aggregator header —
implemented-of-total; the remainder is tracked follow-up, not silent absence.
STIGs ride a quarterly release cycle — see `STANDARDS_UPDATE_REGISTRY.md`.

## Platforms with no official DISA STIG (deliberately not invented here)

| Platform | Status |
|---|---|
| Debian | No official DISA STIG. Use the CIS Debian benchmark (`benchmarks/cis/debian_11/`). |
| Rocky Linux | No official DISA STIG. The RHEL STIG applies in practice as a derivative — assess with `stig/rhel_9` against Rocky facts and document the derivation. |
| nginx | No official DISA STIG (Apache and general Web Server SRG only). CIS nginx guidance where needed. |
| Cloud foundations (AWS/Azure/GCP) | SRGs, not STIGs. CIS Foundations benchmarks (`benchmarks/cis/cloud/`) are the assessable baseline. |
| M365 | Separate per-app Office STIGs exist; deferred. CIS M365 (`benchmarks/cis/saas/m365/`) is the current coverage. |

## Sunset platforms (absent from the current DISA library)

`windows_10`, `windows_server_2016`, `windows_server_2019`, `ubuntu_20_04` —
see `SUNSET.md` in each directory. Content frozen for historical assessments;
successors named per file.
