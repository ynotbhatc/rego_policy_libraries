# Test coverage

> **Generated** — do not edit by hand. Refresh with `python3 scripts/coverage_report.py > COVERAGE.md`

**991 of 1066 policy files have tests (93%).** 1497 test files, 75 policies still uncovered.

## How far each framework has been validated

A passing unit test proves a rule does what its author meant; it does not prove the rule reads what a real
collector sends. Every framework key carries one label, kept in `scripts/coverage_labels.json`:

- **validated**: run against real host or tenant evidence and the results checked; the evidence column says where.
- **partial**: rules implemented and unit-tested, but the evidence or collector is incomplete, or the module
  covers a subset of the benchmark; the evidence column says what is missing.
- **experimental**: generated or new, not yet run on real evidence. Treat its results as unverified.

**195 framework keys: 4 validated, 5 partial, 186 experimental.**

| framework key | label | modules | evidence |
|---|---|---|---|
| `cis_m365_v7` | validated | `benchmarks/cis/saas/m365_v7` | Run against real evidence on a lab and customer estate in November 2026 with the AAC product collectors. |
| `cis_rhel9` | validated | `benchmarks/cis/rhel_9` | Run against real evidence on a lab and customer estate in November 2026 with the AAC product collectors (collector-driven fixes: CHANGELOG, CIS RHEL 9 'found while building the compliance collectors'). |
| `cis_windows_2022` | validated | `benchmarks/cis/windows_server_2022_modular` | Run against real evidence on a lab and customer estate in November 2026 with the AAC product collectors. |
| `cis_windows_server_2022` | validated | `benchmarks/cis/windows_server_2022_modular` | Same module tree as cis_windows_2022. Run against real evidence on a lab and customer estate in November 2026 with the AAC product collectors. |
| `cis_amazon_linux_2023` | partial | `benchmarks/cis/amazon_linux_2023` | Fed real host evidence 2026-11-19; collector gaps open (issue #332). |
| `cis_ubuntu_2204` | partial | `benchmarks/cis/ubuntu_22_04` | Fed real host evidence 2026-11-19; collector gaps open (issue #332). |
| `cis_ubuntu_22_04` | partial | `benchmarks/cis/ubuntu_22_04` | Same module tree as cis_ubuntu_2204. Fed real host evidence 2026-11-19; collector gaps open (issue #332). |
| `stig.rhel_9` | partial | `benchmarks/stig/rhel_9` | V2R10 rules compared with DISA's check text (#320) and run on a real RHEL 9.6 host 2026-11-20, but about 45 fact paths the rules read are not collected yet, so those rules report evidence missing. |
| `stig_rhel9` | partial | `benchmarks/stig/rhel_9` | Bridge onto stig.rhel_9. V2R10 rules compared with DISA's check text (#320) and run on a real RHEL 9.6 host 2026-11-20, but about 45 fact paths the rules read are not collected yet. |
| `aca_155_260` | experimental |  |  |
| `ai_governance` | experimental |  |  |
| `ami_device` | experimental |  |  |
| `ami_headend` | experimental |  |  |
| `ami_nist_ir7628` | experimental |  |  |
| `apra_cps234` | experimental |  |  |
| `as9100d` | experimental |  |  |
| `bnm_rmit` | experimental |  |  |
| `bsi_c5` | experimental |  |  |
| `c2m2` | experimental |  |  |
| `ccpa` | experimental |  |  |
| `cert_in` | experimental |  |  |
| `cert_rmm` | experimental |  |  |
| `cfr_part_11` | experimental |  |  |
| `cis.intune_defender_antivirus` | experimental |  |  |
| `cis.mobile.ios` | experimental |  |  |
| `cis.rhel_10` | experimental |  |  |
| `cis.sql_server_2022` | experimental |  |  |
| `cis.sql_server_2025` | experimental |  |  |
| `cis_aks` | experimental |  |  |
| `cis_aks_automatic` | experimental |  |  |
| `cis_aws` | experimental |  |  |
| `cis_azure` | experimental |  |  |
| `cis_cisco_ios_xe_17` | experimental |  |  |
| `cis_controls_v8` | experimental |  |  |
| `cis_debian_11` | experimental |  |  |
| `cis_debian_12` | experimental |  |  |
| `cis_debian_13` | experimental |  |  |
| `cis_docker` | experimental |  |  |
| `cis_eks` | experimental |  |  |
| `cis_gcp` | experimental |  |  |
| `cis_gke` | experimental |  |  |
| `cis_kubernetes` | experimental |  |  |
| `cis_mcp_server` | experimental |  |  |
| `cis_oci` | experimental |  |  |
| `cis_openshift` | experimental |  |  |
| `cis_opnsense` | experimental |  |  |
| `cis_palo_alto_panos` | experimental |  |  |
| `cis_pfsense` | experimental |  |  |
| `cis_postgresql` | experimental |  |  |
| `cis_postgresql_16` | experimental |  |  |
| `cis_postgresql_18` | experimental |  |  |
| `cis_rhel10` | experimental |  |  |
| `cis_rhel8` | experimental |  |  |
| `cis_rocky_linux_8` | experimental |  |  |
| `cis_rocky_linux_9` | experimental |  |  |
| `cis_suse16` | experimental |  |  |
| `cis_ubuntu_2004` | experimental |  |  |
| `cis_ubuntu_20_04` | experimental |  |  |
| `cis_ubuntu_2404` | experimental |  |  |
| `cis_ubuntu_24_04` | experimental |  |  |
| `cis_ubuntu_26_04` | experimental |  |  |
| `cis_vmware_esxi` | experimental |  |  |
| `cis_vmware_esxi_9` | experimental |  |  |
| `cis_vyos` | experimental |  |  |
| `cis_windows_10` | experimental |  |  |
| `cis_windows_11` | experimental |  |  |
| `cis_windows_2019` | experimental |  |  |
| `cis_windows_server_2016` | experimental |  |  |
| `cis_windows_server_2019` | experimental |  |  |
| `cis_windows_server_2025` | experimental |  |  |
| `cisa_cpg` | experimental |  |  |
| `cisa_ssdaf` | experimental |  |  |
| `cisa_tic3` | experimental |  |  |
| `cjis` | experimental |  |  |
| `cmmc` | experimental |  |  |
| `cms_mars_e` | experimental |  |  |
| `cobit` | experimental |  |  |
| `coppa` | experimental |  |  |
| `cra` | experimental |  |  |
| `crypto_miner_detection` | experimental |  |  |
| `csa_ccm` | experimental |  |  |
| `cyber_essentials` | experimental |  |  |
| `dcc` | experimental |  |  |
| `dfars_7012` | experimental |  |  |
| `digital_sovereignty` | experimental |  |  |
| `dora` | experimental |  |  |
| `dpdp` | experimental |  |  |
| `eo_14028` | experimental |  |  |
| `essential_eight` | experimental |  |  |
| `estate_continuity` | experimental |  |  |
| `eu_ai_act` | experimental |  |  |
| `far_cyber` | experimental |  |  |
| `fedramp` | experimental |  |  |
| `fedramp_20x` | experimental |  |  |
| `ferpa` | experimental |  |  |
| `fisma` | experimental |  |  |
| `ftc_red_flags` | experimental |  |  |
| `gdpr` | experimental |  |  |
| `glba` | experimental |  |  |
| `hipaa` | experimental |  |  |
| `hitrust` | experimental |  |  |
| `hkma_trm` | experimental |  |  |
| `iec_62443` | experimental |  |  |
| `irs_1075` | experimental |  |  |
| `iso27001` | experimental |  |  |
| `iso27701` | experimental | `frameworks/privacy/iso27701` | Not validated: written against ISO/IEC 27701:2019 without the standard's text at hand; the rebuild against the 2019 edition waits for its table of contents (issue #302). Never run on real evidence. |
| `iso_42001` | experimental |  |  |
| `iso_42005` | experimental |  |  |
| `itar` | experimental |  |  |
| `k8s_pss` | experimental |  |  |
| `kubernetes.admission` | experimental |  |  |
| `maritime_33cfr101f` | experimental |  |  |
| `mas_trm` | experimental |  |  |
| `meti_csm` | experimental |  |  |
| `ncsc_caf` | experimental |  |  |
| `nerc_cip` | experimental |  |  |
| `nis2` | experimental |  |  |
| `nispom` | experimental |  |  |
| `nist.ai_600_1` | experimental |  |  |
| `nist.ai_rmf` | experimental |  |  |
| `nist.csf` | experimental |  |  |
| `nist.rmf` | experimental |  |  |
| `nist.sp800_160v2` | experimental |  |  |
| `nist.sp800_171_r2` | experimental |  |  |
| `nist.sp800_171a` | experimental |  |  |
| `nist.sp800_171a_r2` | experimental |  |  |
| `nist.sp800_172` | experimental |  |  |
| `nist.sp800_39` | experimental |  |  |
| `nist.sp800_53` | experimental |  |  |
| `nist_800_171` | experimental |  |  |
| `nist_800_53` | experimental |  |  |
| `nist_800_82` | experimental |  |  |
| `nist_ai_rmf` | experimental |  |  |
| `nist_csf` | experimental |  |  |
| `nist_privacy_framework` | experimental |  |  |
| `nist_ssdf` | experimental |  |  |
| `nrc_73_54` | experimental |  |  |
| `nsa_cisa_k8s` | experimental |  |  |
| `ny_dfs` | experimental |  |  |
| `owasp_llm` | experimental |  |  |
| `owasp_top10` | experimental |  |  |
| `pci_dss` | experimental |  |  |
| `pqc` | experimental |  |  |
| `provider_change` | experimental |  |  |
| `sap_abap_baseline` | experimental |  |  |
| `scuba_m365` | experimental |  |  |
| `sec_cyber` | experimental |  |  |
| `sentinel_ansible` | experimental |  |  |
| `sentinel_dockerfile` | experimental |  |  |
| `sentinel_kubernetes` | experimental |  |  |
| `sentinel_terraform` | experimental |  |  |
| `soc2` | experimental |  |  |
| `sox` | experimental |  |  |
| `stig.amazon_linux_2023` | experimental |  |  |
| `stig.apache_2_4_unix` | experimental |  |  |
| `stig.cisco_ios_xe_router` | experimental |  |  |
| `stig.kubernetes` | experimental |  |  |
| `stig.ms_sql_2016` | experimental |  |  |
| `stig.openshift_4` | experimental |  |  |
| `stig.oracle_database_19c` | experimental |  |  |
| `stig.oracle_linux_8` | experimental |  |  |
| `stig.oracle_linux_9` | experimental |  |  |
| `stig.oracle_mysql_8` | experimental |  |  |
| `stig.postgresql_16` | experimental |  |  |
| `stig.rhel_10` | experimental |  |  |
| `stig.rhel_8` | experimental |  |  |
| `stig.rke2` | experimental |  |  |
| `stig.sles_15` | experimental |  |  |
| `stig.ubuntu_22_04` | experimental |  |  |
| `stig.ubuntu_24_04` | experimental |  |  |
| `stig.vmware_vsphere_8` | experimental |  |  |
| `stig.windows_11` | experimental |  |  |
| `stig.windows_server_2016` | experimental |  |  |
| `stig.windows_server_2019` | experimental |  |  |
| `stig.windows_server_2022` | experimental |  |  |
| `stig.windows_server_2025` | experimental |  |  |
| `stig_amazon_linux_2023` | experimental |  |  |
| `stig_apache_2_4` | experimental |  |  |
| `stig_cisco_ios_xe_router` | experimental |  |  |
| `stig_kubernetes` | experimental |  |  |
| `stig_ms_sql_2016` | experimental |  |  |
| `stig_openshift_4` | experimental |  |  |
| `stig_postgresql_16` | experimental |  |  |
| `stig_rhel8` | experimental |  |  |
| `stig_sles_15` | experimental |  |  |
| `stig_ubuntu_2204` | experimental |  |  |
| `stig_vsphere_8_esxi` | experimental |  |  |
| `stig_windows_11` | experimental |  |  |
| `stig_windows_server_2022` | experimental |  |  |
| `stig_windows_server_2025` | experimental |  |  |
| `swift_csp` | experimental |  |  |
| `tisax` | experimental |  |  |
| `tsa_pipeline` | experimental |  |  |
| `uk_dpa_2018` | experimental |  |  |
| `zero_trust` | experimental |  |  |

## Why this file exists

This library is maintained on a best-effort basis and it is free. Publishing
the gap is cheaper than hiding it, and it answers "where can I help?"
directly — every uncovered policy below is a real, bounded,
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
| `benchmarks/cis` | 35 |
| `benchmarks/stig` | 20 |
| `frameworks/federal` | 6 |
| `benchmarks/sap` | 4 |
| `frameworks/critical_infrastructure` | 2 |
| `enforcement/ansible` | 1 |
| `enforcement/dockerfile` | 1 |
| `enforcement/kubernetes` | 1 |
| `enforcement/terraform` | 1 |
| `frameworks/financial` | 1 |
| `frameworks/management` | 1 |
| `governance/ai` | 1 |
| `threat_detection/crypto_mining` | 1 |

## The queue

<details><summary><code>benchmarks/cis/aks</code> — 1 file(s)</summary>

- `cis_aks_main.rego`

</details>

<details><summary><code>benchmarks/cis/aks_automatic</code> — 1 file(s)</summary>

- `cis_aks_automatic_main.rego`

</details>

<details><summary><code>benchmarks/cis/amazon_linux_2023</code> — 2 file(s)</summary>

- `cis_amazon_linux_2023.rego`
- `cis_amazon_linux_2023_complete.rego`

</details>

<details><summary><code>benchmarks/cis/aws</code> — 1 file(s)</summary>

- `cis_aws_foundations.rego`

</details>

<details><summary><code>benchmarks/cis/azure</code> — 1 file(s)</summary>

- `cis_azure_foundations.rego`

</details>

<details><summary><code>benchmarks/cis/debian_12</code> — 1 file(s)</summary>

- `cis_debian_12.rego`

</details>

<details><summary><code>benchmarks/cis/debian_13</code> — 1 file(s)</summary>

- `cis_debian_13.rego`

</details>

<details><summary><code>benchmarks/cis/docker</code> — 1 file(s)</summary>

- `cis_docker_main.rego`

</details>

<details><summary><code>benchmarks/cis/intune_defender_antivirus</code> — 1 file(s)</summary>

- `cis_intune_defender_antivirus_main.rego`

</details>

<details><summary><code>benchmarks/cis/kubernetes</code> — 1 file(s)</summary>

- `cis_kubernetes_main.rego`

</details>

<details><summary><code>benchmarks/cis/mobile_devices/ios</code> — 1 file(s)</summary>

- `cis_mobile_ios_main.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/cisco_ios_xe_17</code> — 1 file(s)</summary>

- `cis_cisco_ios_xe_17_main.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/palo_alto</code> — 1 file(s)</summary>

- `cis_palo_alto_panos_main.rego`

</details>

<details><summary><code>benchmarks/cis/openshift</code> — 1 file(s)</summary>

- `cis_openshift_main.rego`

</details>

<details><summary><code>benchmarks/cis/rhel_10</code> — 1 file(s)</summary>

- `cis_rhel10_key_main.rego`

</details>

<details><summary><code>benchmarks/cis/rhel_8</code> — 2 file(s)</summary>

- `cis_rhel8_complete.rego`
- `l2_validation.rego`

</details>

<details><summary><code>benchmarks/cis/rocky_linux_8</code> — 2 file(s)</summary>

- `cis_rocky_linux_8_complete.rego`
- `l2_validation.rego`

</details>

<details><summary><code>benchmarks/cis/rocky_linux_9</code> — 2 file(s)</summary>

- `cis_rocky_linux_9_complete.rego`
- `l2_validation.rego`

</details>

<details><summary><code>benchmarks/cis/sql_server_2022</code> — 1 file(s)</summary>

- `cis_sql_server_2022_main.rego`

</details>

<details><summary><code>benchmarks/cis/sql_server_2025</code> — 1 file(s)</summary>

- `cis_sql_server_2025_main.rego`

</details>

<details><summary><code>benchmarks/cis/suse_16</code> — 1 file(s)</summary>

- `cis_suse_16.rego`

</details>

<details><summary><code>benchmarks/cis/ubuntu_20_04</code> — 1 file(s)</summary>

- `cis_ubuntu_2004_key_main.rego`

</details>

<details><summary><code>benchmarks/cis/ubuntu_22_04</code> — 2 file(s)</summary>

- `cis_ubuntu_2204_key_main.rego`
- `cis_ubuntu_22_04.rego`

</details>

<details><summary><code>benchmarks/cis/ubuntu_24_04</code> — 2 file(s)</summary>

- `cis_ubuntu_2404_key_main.rego`
- `cis_ubuntu_24_04.rego`

</details>

<details><summary><code>benchmarks/cis/ubuntu_26_04</code> — 1 file(s)</summary>

- `cis_ubuntu_26_04.rego`

</details>

<details><summary><code>benchmarks/cis/vmware/esxi</code> — 1 file(s)</summary>

- `cis_vmware_esxi_main.rego`

</details>

<details><summary><code>benchmarks/cis/vmware/esxi_9</code> — 1 file(s)</summary>

- `cis_vmware_esxi_9_main.rego`

</details>

<details><summary><code>benchmarks/cis/windows_server_2019_modular</code> — 1 file(s)</summary>

- `cis_windows_2019_key_main.rego`

</details>

<details><summary><code>benchmarks/cis/windows_server_2022_modular</code> — 1 file(s)</summary>

- `cis_windows_2022_key_main.rego`

</details>

<details><summary><code>benchmarks/sap/abap</code> — 4 file(s)</summary>

- `mapping_baseline.rego`
- `mapping_dsag.rego`
- `mapping_nist_csf_2_0.rego`
- `sap_abap_baseline_registry.rego`

</details>

<details><summary><code>benchmarks/stig/amazon_linux_2023</code> — 1 file(s)</summary>

- `stig_amazon_linux_2023_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/apache_2_4_unix</code> — 1 file(s)</summary>

- `stig_apache_2_4_main.rego`

</details>

<details><summary><code>benchmarks/stig/cisco_ios_xe_router</code> — 1 file(s)</summary>

- `stig_cisco_ios_xe_router_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/kubernetes</code> — 1 file(s)</summary>

- `stig_kubernetes_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/ms_sql_2016</code> — 1 file(s)</summary>

- `stig_ms_sql_2016_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/openshift_4</code> — 1 file(s)</summary>

- `stig_openshift_4_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/oracle_linux_8</code> — 1 file(s)</summary>

- `stig_oracle_linux_8_complete.rego`

</details>

<details><summary><code>benchmarks/stig/oracle_linux_9</code> — 1 file(s)</summary>

- `stig_oracle_linux_9_complete.rego`

</details>

<details><summary><code>benchmarks/stig/postgresql_16</code> — 1 file(s)</summary>

- `stig_postgresql_16_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/rhel_10</code> — 1 file(s)</summary>

- `stig_rhel_10_complete.rego`

</details>

<details><summary><code>benchmarks/stig/rhel_8</code> — 2 file(s)</summary>

- `stig_rhel8_complete.rego`
- `stig_rhel8_main.rego`

</details>

<details><summary><code>benchmarks/stig/rhel_9</code> — 2 file(s)</summary>

- `stig_rhel9_complete.rego`
- `stig_rhel9_main.rego`

</details>

<details><summary><code>benchmarks/stig/sles_15</code> — 1 file(s)</summary>

- `stig_sles_15_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/ubuntu_22_04</code> — 1 file(s)</summary>

- `stig_ubuntu_2204_main.rego`

</details>

<details><summary><code>benchmarks/stig/vmware_vsphere_8</code> — 1 file(s)</summary>

- `stig_vsphere_8_esxi_main.rego`

</details>

<details><summary><code>benchmarks/stig/windows_11</code> — 1 file(s)</summary>

- `stig_windows_11_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/windows_server_2022</code> — 1 file(s)</summary>

- `stig_windows_server_2022_key_main.rego`

</details>

<details><summary><code>benchmarks/stig/windows_server_2025</code> — 1 file(s)</summary>

- `stig_windows_server_2025_key_main.rego`

</details>

<details><summary><code>enforcement/ansible</code> — 1 file(s)</summary>

- `sentinel_ansible_main.rego`

</details>

<details><summary><code>enforcement/dockerfile</code> — 1 file(s)</summary>

- `sentinel_dockerfile_main.rego`

</details>

<details><summary><code>enforcement/kubernetes</code> — 1 file(s)</summary>

- `sentinel_kubernetes_main.rego`

</details>

<details><summary><code>enforcement/terraform</code> — 1 file(s)</summary>

- `sentinel_terraform_main.rego`

</details>

<details><summary><code>frameworks/critical_infrastructure/iec_62443</code> — 1 file(s)</summary>

- `iec_62443_key_main.rego`

</details>

<details><summary><code>frameworks/critical_infrastructure/nerc_cip</code> — 1 file(s)</summary>

- `nerc_cip_key_main.rego`

</details>

<details><summary><code>frameworks/federal/cmmc</code> — 1 file(s)</summary>

- `cmmc_key_main.rego`

</details>

<details><summary><code>frameworks/federal/nist/ai_rmf</code> — 2 file(s)</summary>

- `nist_ai_rmf.rego`
- `nist_ai_rmf_key_main.rego`

</details>

<details><summary><code>frameworks/federal/nist/cybersecurity_framework_2.0</code> — 1 file(s)</summary>

- `nist_csf_key_main.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_53</code> — 2 file(s)</summary>

- `nist_800_53_index.rego`
- `nist_800_53_key_main.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/security_testing</code> — 1 file(s)</summary>

- `requirement_11.rego`

</details>

<details><summary><code>frameworks/management/iso27001</code> — 1 file(s)</summary>

- `iso27001_main.rego`

</details>

<details><summary><code>governance/ai</code> — 1 file(s)</summary>

- `ai_governance_main.rego`

</details>

<details><summary><code>threat_detection/crypto_mining</code> — 1 file(s)</summary>

- `crypto_miner_detection_main.rego`

</details>

