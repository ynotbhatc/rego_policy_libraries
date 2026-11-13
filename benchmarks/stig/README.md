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
Compilation before stamping** (October 2026 library: the seven Linux platforms and the five
Windows platforms verified 2026-11-10, the four Oracle platforms verified 2026-10-13; Kubernetes
V2R6 and RGS RKE2 V2R7 against DISA's standalone STIG zips, verified 2026-10-21).
Coverage per platform is stated in each aggregator header —
implemented-of-total; the remainder is tracked follow-up, not silent absence.
STIGs ride a quarterly release cycle — see `STANDARDS_UPDATE_REGISTRY.md`.

## Linux platforms (October 2026 library, verified 2026-11-10)

| Directory | STIG | Rules | How |
|---|---|---|---|
| `rhel_9` | V2R10, 30 Sep 2026 | 104 of 445 | Re-stamped by what each rule checks (`tools/stig_generators/stamp_catalog.py`): every finding keyed on its fact against the V2R10 check text; 39 findings with no V2R10 rule removed. |
| `rhel_8` | V2R8, 01 Jul 2026 | 53 of 369 | Same re-stamp. RHEL 8 is absent from the October 2026 compilation (the standalone zip is still served), so treat V2R8 as its final release. |
| `rhel_10` | V1R2, 01 Jul 2026 | 98 of 434 | Derived from the re-stamped RHEL 9 modules by DISA rule title (`gen_oracle_linux.py rhel_10`, 45 reviewed overrides). The October compilation lists V1R3; re-stamp pending. |
| `ubuntu_22_04` | V2R10, 30 Sep 2026 | 22 of 191 | `tools/stig_generators/gen_linux.py`, catalog id hard-gate. |
| `ubuntu_24_04` | V1R7, 30 Sep 2026 | 22 of 195 | The 22.04 logic table re-keyed by title (`UBTU_22_TO_24`); sshd Ciphers and MACs from the 24.04 check text. |
| `amazon_linux_2023` | V1R5, 30 Sep 2026 | 23 of 187 | `gen_linux.py`. |
| `sles_15` | V2R9, 30 Sep 2026 | 27 of 220 | `gen_linux.py`. |

## Windows platforms (October 2026 library, verified 2026-11-10)

| Platform | STIG | Rules | How it was built |
|---|---|---|---|
| `windows_11` | V2R11, 30 Sep 2026 | 117 of 257 | `tools/stig_generators/gen_windows.py`: every rule whose check is one or more registry value blocks, read as DISA writes them (exact, `in {…}` for "X, Y, or Z", `<=`/`>=` bounds, "excluding 0", "or if the Value Name does not exist" as a second rule body, numeric REG_SZ by `to_number`). The remainder are non-registry checks (audit policy, user rights, services, certificates, documentation) — tracked follow-up. |
| `windows_server_2016` | V2R10, 15 Jan 2025 | 103 of 273 | Same generator. Returned to the DISA library (it was marked sunset against the July 2026 compilation); replaces the 5-finding hand-written stub, whose ids were Server 2022's. |
| `windows_server_2019` | V3R9, 01 Jul 2026 | 104 of 282 | Same generator; same return and same replaced stub. |
| `windows_server_2022` | V2R11, 30 Sep 2026 | 103 of 277 | Same generator. |
| `windows_server_2025` | V1R4, 30 Sep 2026 | 94 of 291 | Same generator. WN25-DC-000320 moved under an unchanged title: the check now reads `LDAPServerEnforceIntegrity = 1`, not `LDAPServerIntegrity = 2`. |

Every generated rule's `stig_id`, `vuln_id`, severity and title come from the XCCDF; the rule
bodies are derived, not copied. Windows 10 left the library (final V3R6) — see `SUNSET.md`.

## Oracle platforms (October 2026 library)

| Platform | Rules | How it was built |
|---|---|---|
| `oracle_linux_9` (OL09, V1R7) | 93 of 450 | Derived from the RHEL 9 modules by DISA rule title (`tools/stig_generators/gen_oracle_linux.py`): OL 9 and RHEL 9 share the rule text, so a RHEL rule whose title matches an OL rule is emitted with the OL id, vuln id, severity and title from the OL XCCDF; 45 pairs the title match misses are reviewed overrides, 6 look-alike titles are refused. The remaining 357 rules are tracked follow-up. |
| `oracle_linux_8` (OL08, V2R10) | 68 of 378 | Same derivation from the Oracle Linux 9 modules (105 of OL 8's titles are OL 9 titles verbatim); 22 reviewed overrides. |
| `oracle_database_19c` (O19C, V1R6) | 96 of 96 | Every rule (`tools/stig_generators/gen_oracle_db.py`): 51 read the value DISA's check queries (V$PARAMETER, DBA_PROFILES, privilege and object queries), 45 are attestation booleans because DISA's check is a documentation or procedure review. |
| `oracle_mysql_8` (MYS8, V2R3) | 100 of 100 | Every rule, same generator: 65 read global variables, plugin status, audit filters and user rows; 35 are attestations. |

All four join the 800-53 spine (`crosswalk/stig_800_53/data.json`, every catalog rule, via the CCI list).

**Resolved 2026-11-10:** the RHEL 9 modules' `stig_id`/`vuln_id` values had disagreed with
the catalog for 108 of 143 findings. Both RHEL 9 and RHEL 8 were re-stamped by what each rule
checks (`tools/stig_generators/stamp_catalog.py`), and the Oracle overrides were re-keyed to
the stamped ids (53 keys moved, 8 removed). The Oracle modules themselves are unchanged.

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

`windows_10` — removed 2026-11-10, see [`SUNSET.md`](SUNSET.md) (DISA's final release is V3R6).
`ubuntu_20_04` — see `SUNSET.md` in its directory; content frozen for historical assessments.
`windows_server_2016` and `windows_server_2019` were listed here against the July 2026
compilation; the October 2026 library ships both (V2R10, V3R9) and they are generated platforms again.

Observed in the October 2026 compilation: RHEL 8 is no longer shipped (the module stays on the
standalone V2R8 zip); RHEL 10 is listed at V1R3 against the module's V1R2 (re-stamp pending);
WebLogic 12c and Oracle HTTP Server have left the library (the standalone WebLogic 12c V2R2 zip
is still served).
