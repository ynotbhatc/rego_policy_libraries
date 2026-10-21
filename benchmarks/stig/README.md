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
Compilation before stamping** (July 2026 library, verified 2026-09-03; the
four Oracle platforms against the October 2026 library, verified 2026-10-13; Kubernetes V2R6 and
RGS RKE2 V2R7 against DISA's standalone STIG zips, verified 2026-10-21).
Coverage per platform is stated honestly in each aggregator header —
implemented-of-total; the remainder is tracked follow-up, not silent absence.
STIGs ride a quarterly release cycle — see `STANDARDS_UPDATE_REGISTRY.md`.

## Oracle platforms (October 2026 library)

| Platform | Rules | How it was built |
|---|---|---|
| `oracle_linux_9` (OL09, V1R7) | 93 of 450 | Derived from the RHEL 9 modules by DISA rule title (`tools/stig_generators/gen_oracle_linux.py`): OL 9 and RHEL 9 share the rule text, so a RHEL rule whose title matches an OL rule is emitted with the OL id, vuln id, severity and title from the OL XCCDF; 45 pairs the title match misses are reviewed overrides, 6 look-alike titles are refused. The remaining 357 rules are tracked follow-up. |
| `oracle_linux_8` (OL08, V2R10) | 68 of 378 | Same derivation from the Oracle Linux 9 modules (105 of OL 8's titles are OL 9 titles verbatim); 22 reviewed overrides. |
| `oracle_database_19c` (O19C, V1R6) | 96 of 96 | Every rule (`tools/stig_generators/gen_oracle_db.py`): 51 read the value DISA's check queries (V$PARAMETER, DBA_PROFILES, privilege and object queries), 45 are attestation booleans because DISA's check is a documentation or procedure review. |
| `oracle_mysql_8` (MYS8, V2R3) | 100 of 100 | Every rule, same generator: 65 read global variables, plugin status, audit filters and user rows; 35 are attestations. |

All four join the 800-53 spine (`crosswalk/stig_800_53/data.json`, every catalog rule, via the CCI list).

**Known defect, tracked:** the RHEL 9 modules' `stig_id`/`vuln_id` values disagree with
the current RHEL 9 catalog for 108 of 143 findings (the title next to the logic names a
different DISA rule than the id does). The Oracle derivation keys on the title, not the id,
for exactly this reason. Re-stamping the RHEL 9 ids by title is the next STIG item.

## Kubernetes and RKE2 (every rule, verified 2026-10-21)

| Platform | Rules | How it was built |
|---|---|---|
| `kubernetes` (CNTR-K8, V2R6, 01 Apr 2026) | 92 of 92 | Every rule (`tools/stig_generators/gen_k8s.py`, two-way catalog gate): 84 machine-checked from manifest flags, kubelet args and KubeletConfiguration, file modes/ownership, cluster state (images, namespaces, dashboard pods, host ports, kubectl versions); 1 flag check plus an attestation; 7 attestations (PPSM CAL reviews, sensitive data, Secret access, user pods in system namespaces). |
| `rke2` (CNTR-R2, V2R7, 01 Jul 2026) | 21 of 21 | Same generator, RKE2's own contract: `/etc/rancher/rke2/config.yaml`, the component args RKE2 renders, the audit and Pod Security admission files, and the file table under `/etc/rancher/rke2` and `/var/lib/rancher/rke2`. 15 machine-checked, 1 machine plus attestation, 5 attestations (Carbide image signatures, essential components, PPSM CAL, sensitive env values, supported version). |

Both fail closed rule by rule: a finding whose evidence was not collected is Open with
`detail` "<STIG-ID>: evidence missing — <field> not collected", and an attestation is Open until
`input.attest.<key>` is true. Both join the 800-53 spine (K8: 92 of 92; R2: 20 of 21 — CNTR-R2-000460's
CCI has no Rev 5 mapping in the CCI list). `openshift_4` remains partial (CAT I + selected CAT II).

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

Observed in the October 2026 library (not yet acted on): RHEL 8 is no longer
shipped (RHEL 10 V1R3 is); WebLogic 12c and Oracle HTTP Server have left the
library (the standalone WebLogic 12c V2R2 zip is still served).
