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
Compilation before stamping** (the Linux platforms against the October 2026 library, verified
2026-11-10; the four Oracle platforms against the October 2026 library, verified 2026-10-13; the
Windows and application platforms against the July 2026 library, verified 2026-09-03; Kubernetes V2R6 and
RGS RKE2 V2R7 against DISA's standalone STIG zips, verified 2026-10-21).
Coverage per platform is stated honestly in each aggregator header —
implemented-of-total; the remainder is tracked follow-up, not silent absence.
STIGs ride a quarterly release cycle — see `STANDARDS_UPDATE_REGISTRY.md`.

## Linux platforms (October 2026 library, verified 2026-11-10)

| Platform | Rules | How it was built |
|---|---|---|
| `rhel_9` (RHEL-09, V2R10) | 104 of 445 | Hand-maintained modules, **re-stamped by what each rule checks** (`tools/stig_generators/stamp_catalog.py`): every finding was reviewed against the V2R10 check text and carries the stig_id, vuln_id, severity and title of the DISA rule its logic implements; 39 findings whose fact has no V2R10 rule (or duplicated another block) were removed. The remaining 341 rules are tracked follow-up. |
| `rhel_8` (RHEL-08, V2R8) | 53 of 369 | Same re-stamp; 20 findings removed (the RHEL 8 STIG has no `/etc/passwd`, `/etc/shadow`, `/etc/group` mode rules and no sshd IgnoreRhosts / HostbasedAuthentication / UsePAM rules). The remaining 316 are tracked follow-up. Note DISA no longer ships RHEL 8 in the compilation; V2R8 is the last standalone release. |
| `rhel_10` (RHEL-10, V1R2) | 98 of 434 | Derived from the RHEL 9 modules by DISA rule title (`tools/stig_generators/gen_oracle_linux.py rhel_10`): 45 reviewed overrides where RHEL 10 reworded the title, 1 look-alike refused; 6 RHEL 9 rules have no RHEL 10 counterpart. The remaining 336 are tracked follow-up. |
| `ubuntu_22_04` (UBTU-22, V2R10) | 22 of 191 | Generated from the hand-authored logic table (`tools/stig_generators/gen_linux.py`), all 15 CAT I plus selected CAT II; catalog id hard-gate. |
| `ubuntu_24_04` (UBTU-24, V1R7) | 22 of 195 | The Ubuntu 22.04 table re-keyed by DISA rule title (`UBTU_22_TO_24` in `gen_linux.py`); only the sshd Ciphers and MACs values differ. 15 of 17 CAT I. |
| `amazon_linux_2023` (AZLX-23, V1R5) | 23 of 187 | Generated from the logic table; 19 of 21 CAT I. |
| `sles_15` (SLES-15, V2R9) | 27 of 220 | Generated from the logic table; 25 of 26 CAT I. |

The RHEL 9 id defect recorded on 2026-10-13 (ids naming a different rule than the logic) is closed by the
re-stamp: `stamp_catalog.py` keys every finding on its fact, prints every mapping, and refuses a title match
by similarity alone. A rule whose logic checks only `net.ipv4.conf.all.*` is stamped on DISA's `all` rule;
the `default.*` rule is uncovered, not invented.

## Oracle platforms (October 2026 library)

| Platform | Rules | How it was built |
|---|---|---|
| `oracle_linux_9` (OL09, V1R7) | 93 of 450 | Derived from the RHEL 9 modules by DISA rule title (`tools/stig_generators/gen_oracle_linux.py`): OL 9 and RHEL 9 share the rule text, so a RHEL rule whose title matches an OL rule is emitted with the OL id, vuln id, severity and title from the OL XCCDF; 45 pairs the title match misses are reviewed overrides, 6 look-alike titles are refused. The remaining 357 rules are tracked follow-up. |
| `oracle_linux_8` (OL08, V2R10) | 68 of 378 | Same derivation from the Oracle Linux 9 modules (105 of OL 8's titles are OL 9 titles verbatim); 22 reviewed overrides. |
| `oracle_database_19c` (O19C, V1R6) | 96 of 96 | Every rule (`tools/stig_generators/gen_oracle_db.py`): 51 read the value DISA's check queries (V$PARAMETER, DBA_PROFILES, privilege and object queries), 45 are attestation booleans because DISA's check is a documentation or procedure review. |
| `oracle_mysql_8` (MYS8, V2R3) | 100 of 100 | Every rule, same generator: 65 read global variables, plugin status, audit filters and user rows; 35 are attestations. |

All four join the 800-53 spine (`crosswalk/stig_800_53/data.json`, every catalog rule, via the CCI list).

**Closed 2026-11-10:** the RHEL 9 modules' `stig_id`/`vuln_id` values disagreed with the
RHEL 9 catalog for 108 of 143 findings (the title next to the logic named a different DISA rule
than the id did); the Oracle derivation keyed on the title for exactly this reason. The re-stamp
above fixed the ids, and `gen_oracle_linux.py`'s override keys were moved to the stamped ids (8 keys
whose source blocks were retired are gone, so a future Oracle regeneration drops the rules they produced;
the Oracle modules are unchanged in this release).

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

Observed in the October 2026 library: RHEL 8 is no longer shipped in the compilation
(`rhel_8` here is stamped from the last standalone release, V2R8); RHEL 10 is (added here from the
standalone V1R2 zip — if the compilation carries a later release, re-run `parse_xccdf.py` and
`gen_oracle_linux.py rhel_10`); WebLogic 12c and Oracle HTTP Server have left the library (the
standalone WebLogic 12c V2R2 zip is still served).
