# Test coverage

> **Generated** — do not edit by hand. Refresh with `python3 scripts/coverage_report.py > COVERAGE.md`

**978 of 1052 policy files have tests (93%).** 1415 test files, 74 policies still uncovered.

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
| `frameworks/federal` | 5 |
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

<details><summary><code>frameworks/federal/nist/sp_800_53</code> — 1 file(s)</summary>

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

