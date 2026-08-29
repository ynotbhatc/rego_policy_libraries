# Test coverage

> **Generated** — do not edit by hand. Refresh with `python3 scripts/coverage_report.py > COVERAGE.md`

**82 of 558 policy files have tests (15%).** 86 test files, 476 policies still uncovered.

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
| `benchmarks/cis` | 233 |
| `frameworks/federal` | 51 |
| `frameworks/critical_infrastructure` | 43 |
| `frameworks/management` | 38 |
| `frameworks/compliance` | 24 |
| `benchmarks/stig` | 20 |
| `frameworks/privacy` | 19 |
| `frameworks/financial` | 15 |
| `frameworks/sovereignty` | 11 |
| `governance/geisa` | 6 |
| `governance/eu_ai_act` | 5 |
| `governance/ai` | 3 |
| `enforcement/kubernetes` | 2 |
| `enforcement/ansible` | 1 |
| `enforcement/cicd` | 1 |
| `enforcement/dockerfile` | 1 |
| `enforcement/git` | 1 |
| `enforcement/supply_chain` | 1 |
| `enforcement/terraform` | 1 |

## The queue

<details><summary><code>benchmarks/cis/amazon_linux_2023</code> — 16 file(s)</summary>

- `auditd_validation.rego`
- `boot_security_validation.rego`
- `cis_amazon_linux_2023.rego`
- `cis_amazon_linux_2023_main.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `selinux_validation.rego`
- `service_validation.rego`
- `ssh_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/aws</code> — 3 file(s)</summary>

- `cis_aws_foundations.rego`
- `cis_aws_main.rego`
- `l2_validation.rego`

</details>

<details><summary><code>benchmarks/cis/azure</code> — 3 file(s)</summary>

- `cis_azure_foundations.rego`
- `cis_azure_main.rego`
- `l2_validation.rego`

</details>

<details><summary><code>benchmarks/cis/cloud/aws/01_identity_access_management</code> — 1 file(s)</summary>

- `iam.rego`

</details>

<details><summary><code>benchmarks/cis/cloud/azure/01_identity_access_management</code> — 1 file(s)</summary>

- `azure_iam.rego`

</details>

<details><summary><code>benchmarks/cis/cloud/gcp</code> — 1 file(s)</summary>

- `cis_gcp_main.rego`

</details>

<details><summary><code>benchmarks/cis/containers/01_host_configuration</code> — 1 file(s)</summary>

- `host_config.rego`

</details>

<details><summary><code>benchmarks/cis/containers/kubernetes/01_master_node_security</code> — 1 file(s)</summary>

- `master_node.rego`

</details>

<details><summary><code>benchmarks/cis/databases/oracle_legacy</code> — 1 file(s)</summary>

- `cis_oracle_complete.rego`

</details>

<details><summary><code>benchmarks/cis/databases/oracle_legacy/modules</code> — 4 file(s)</summary>

- `database_parameters.rego`
- `installation_patches.rego`
- `listener_configuration.rego`
- `user_account_management.rego`

</details>

<details><summary><code>benchmarks/cis/debian_11</code> — 15 file(s)</summary>

- `apparmor_validation.rego`
- `auditd_validation.rego`
- `boot_security_validation.rego`
- `cis_debian_11_main.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `services_validation.rego`
- `ssh_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/docker</code> — 2 file(s)</summary>

- `cis_docker_benchmark.rego`
- `cis_docker_main.rego`

</details>

<details><summary><code>benchmarks/cis/gcp</code> — 2 file(s)</summary>

- `cis_gcp_foundations.rego`
- `l2_validation.rego`

</details>

<details><summary><code>benchmarks/cis/kubernetes</code> — 3 file(s)</summary>

- `cis_kubernetes_benchmark.rego`
- `cis_kubernetes_main.rego`
- `l2_validation.rego`

</details>

<details><summary><code>benchmarks/cis/mobile_devices/android</code> — 1 file(s)</summary>

- `android_security.rego`

</details>

<details><summary><code>benchmarks/cis/mobile_devices/ios</code> — 1 file(s)</summary>

- `ios_security.rego`

</details>

<details><summary><code>benchmarks/cis/network/cisco</code> — 1 file(s)</summary>

- `cisco_security.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/arista</code> — 1 file(s)</summary>

- `cis_arista_eos.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/cisco</code> — 1 file(s)</summary>

- `cis_cisco_ios.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/fortinet</code> — 1 file(s)</summary>

- `cis_fortinet_fortigate.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/juniper</code> — 1 file(s)</summary>

- `cis_juniper_junos.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/palo_alto</code> — 1 file(s)</summary>

- `cis_palo_alto_panos.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/pfsense</code> — 2 file(s)</summary>

- `cis_pfsense.rego`
- `cis_pfsense_main.rego`

</details>

<details><summary><code>benchmarks/cis/network_devices/vyos</code> — 2 file(s)</summary>

- `cis_vyos.rego`
- `cis_vyos_main.rego`

</details>

<details><summary><code>benchmarks/cis/nginx</code> — 1 file(s)</summary>

- `cis_nginx_1_20.rego`

</details>

<details><summary><code>benchmarks/cis/openshift</code> — 1 file(s)</summary>

- `cis_openshift_4.rego`

</details>

<details><summary><code>benchmarks/cis/os/linux/redhat</code> — 4 file(s)</summary>

- `access_control.rego`
- `cis_policy.rego`
- `filesystem.rego`
- `network.rego`

</details>

<details><summary><code>benchmarks/cis/os/linux/rhel_9_legacy/modules</code> — 3 file(s)</summary>

- `pam_validation.rego`
- `ssh_validation.rego`
- `user_accounts_validation.rego`

</details>

<details><summary><code>benchmarks/cis/os/linux/ubuntu/01_initial_setup</code> — 1 file(s)</summary>

- `filesystem.rego`

</details>

<details><summary><code>benchmarks/cis/os/windows/server_2022</code> — 1 file(s)</summary>

- `windows_security.rego`

</details>

<details><summary><code>benchmarks/cis/rhel_10</code> — 1 file(s)</summary>

- `cis_rhel10_main.rego`

</details>

<details><summary><code>benchmarks/cis/rhel_8</code> — 15 file(s)</summary>

- `auditd_validation.rego`
- `cis_rhel8_main.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `l2_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `selinux_validation.rego`
- `services_validation.rego`
- `ssh_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/rhel_9</code> — 20 file(s)</summary>

- `auditd_validation.rego`
- `authorized_keys_validation.rego`
- `boot_security_validation.rego`
- `certificate_validation.rego`
- `cis_rhel9_main.rego`
- `cis_rhel_9.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `l2_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `selinux_validation.rego`
- `service_validation.rego`
- `ssh_validation.rego`
- `storage_encryption_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/rocky_linux_8</code> — 14 file(s)</summary>

- `auditd_validation.rego`
- `cis_rocky_linux_8_main.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `selinux_validation.rego`
- `services_validation.rego`
- `ssh_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/rocky_linux_9</code> — 14 file(s)</summary>

- `auditd_validation.rego`
- `cis_rocky_linux_9_main.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `selinux_validation.rego`
- `services_validation.rego`
- `ssh_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/saas/m365</code> — 5 file(s)</summary>

- `defender_validation.rego`
- `fabric_validation.rego`
- `purview_validation.rego`
- `sharepoint_validation.rego`
- `teams_validation.rego`

</details>

<details><summary><code>benchmarks/cis/saas/m365_v7</code> — 11 file(s)</summary>

- `admin_center_validation.rego`
- `attestation_validation.rego`
- `cis_m365_v7_complete.rego`
- `defender_validation.rego`
- `entra_validation.rego`
- `exchange_validation.rego`
- `fabric_validation.rego`
- `intune_validation.rego`
- `purview_validation.rego`
- `sharepoint_validation.rego`
- `teams_validation.rego`

</details>

<details><summary><code>benchmarks/cis/ubuntu_20_04</code> — 15 file(s)</summary>

- `apparmor_validation.rego`
- `auditd_validation.rego`
- `boot_security_validation.rego`
- `cis_ubuntu_2004_main.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `services_validation.rego`
- `ssh_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/ubuntu_22_04</code> — 16 file(s)</summary>

- `apparmor_validation.rego`
- `auditd_validation.rego`
- `boot_security_validation.rego`
- `cis_ubuntu_2204_main.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `l2_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `services_validation.rego`
- `ssh_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/ubuntu_24_04</code> — 16 file(s)</summary>

- `apparmor_validation.rego`
- `auditd_validation.rego`
- `boot_security_validation.rego`
- `cis_ubuntu_2404_main.rego`
- `cron_validation.rego`
- `file_permissions_validation.rego`
- `filesystem_validation.rego`
- `initial_setup_validation.rego`
- `l2_validation.rego`
- `logging_validation.rego`
- `network_validation.rego`
- `pam_validation.rego`
- `services_validation.rego`
- `ssh_validation.rego`
- `sudo_validation.rego`
- `user_group_validation.rego`

</details>

<details><summary><code>benchmarks/cis/vmware/esxi</code> — 1 file(s)</summary>

- `cis_esxi_8.rego`

</details>

<details><summary><code>benchmarks/cis/vmware/vcenter</code> — 1 file(s)</summary>

- `cis_vcenter_8.rego`

</details>

<details><summary><code>benchmarks/cis/web_servers/apache</code> — 1 file(s)</summary>

- `apache_security.rego`

</details>

<details><summary><code>benchmarks/cis/web_servers/mysql</code> — 1 file(s)</summary>

- `mysql_security.rego`

</details>

<details><summary><code>benchmarks/cis/web_servers/nginx</code> — 1 file(s)</summary>

- `nginx_security.rego`

</details>

<details><summary><code>benchmarks/cis/windows_10</code> — 1 file(s)</summary>

- `cis_windows_10.rego`

</details>

<details><summary><code>benchmarks/cis/windows_server_2016</code> — 1 file(s)</summary>

- `cis_windows_server_2016.rego`

</details>

<details><summary><code>benchmarks/cis/windows_server_2019_modular</code> — 10 file(s)</summary>

- `account_policies_validation.rego`
- `advanced_audit_validation.rego`
- `bitlocker_validation.rego`
- `cis_windows_2019_main.rego`
- `event_log_validation.rego`
- `local_policies_validation.rego`
- `registry_validation.rego`
- `security_options_validation.rego`
- `system_services_validation.rego`
- `windows_defender_validation.rego`

</details>

<details><summary><code>benchmarks/cis/windows_server_2022</code> — 1 file(s)</summary>

- `cis_windows_server_2022.rego`

</details>

<details><summary><code>benchmarks/cis/windows_server_2022_modular</code> — 11 file(s)</summary>

- `account_policies_validation.rego`
- `advanced_audit_validation.rego`
- `bitlocker_validation.rego`
- `cis_windows_2022_main.rego`
- `event_log_validation.rego`
- `l2_validation.rego`
- `local_policies_validation.rego`
- `registry_validation.rego`
- `security_options_validation.rego`
- `system_services_validation.rego`
- `windows_defender_validation.rego`

</details>

<details><summary><code>benchmarks/stig/kubernetes</code> — 1 file(s)</summary>

- `stig_kubernetes_complete.rego`

</details>

<details><summary><code>benchmarks/stig/openshift_4</code> — 1 file(s)</summary>

- `stig_openshift_4_complete.rego`

</details>

<details><summary><code>benchmarks/stig/rhel_8</code> — 7 file(s)</summary>

- `account_auth.rego`
- `audit_logging.rego`
- `configuration_management.rego`
- `file_permissions.rego`
- `network.rego`
- `services.rego`
- `ssh_config.rego`

</details>

<details><summary><code>benchmarks/stig/rhel_9</code> — 9 file(s)</summary>

- `account_auth.rego`
- `audit_logging.rego`
- `configuration_management.rego`
- `file_permissions.rego`
- `network.rego`
- `pki_crypto.rego`
- `services.rego`
- `software_integrity.rego`
- `ssh_config.rego`

</details>

<details><summary><code>benchmarks/stig/windows_server_2022</code> — 2 file(s)</summary>

- `configuration_management.rego`
- `services_audit.rego`

</details>

<details><summary><code>enforcement/ansible</code> — 1 file(s)</summary>

- `sentinel_ansible.rego`

</details>

<details><summary><code>enforcement/cicd</code> — 1 file(s)</summary>

- `cicd_pipeline.rego`

</details>

<details><summary><code>enforcement/dockerfile</code> — 1 file(s)</summary>

- `sentinel_dockerfile.rego`

</details>

<details><summary><code>enforcement/git</code> — 1 file(s)</summary>

- `playbook_documentation.rego`

</details>

<details><summary><code>enforcement/kubernetes</code> — 2 file(s)</summary>

- `kubernetes_admission.rego`
- `sentinel_kubernetes.rego`

</details>

<details><summary><code>enforcement/supply_chain</code> — 1 file(s)</summary>

- `slsa_governance.rego`

</details>

<details><summary><code>enforcement/terraform</code> — 1 file(s)</summary>

- `sentinel_terraform.rego`

</details>

<details><summary><code>frameworks/compliance/cra/authorised_representative</code> — 1 file(s)</summary>

- `cra_authorised_representative.rego`

</details>

<details><summary><code>frameworks/compliance/cra/conformity_assessment</code> — 1 file(s)</summary>

- `cra_conformity_assessment.rego`

</details>

<details><summary><code>frameworks/compliance/cra/crypto_evidence</code> — 1 file(s)</summary>

- `cra_crypto_evidence.rego`

</details>

<details><summary><code>frameworks/compliance/cra/declaration_of_conformity</code> — 1 file(s)</summary>

- `cra_declaration_of_conformity.rego`

</details>

<details><summary><code>frameworks/compliance/cra/distributor_obligations</code> — 1 file(s)</summary>

- `cra_distributor_obligations.rego`

</details>

<details><summary><code>frameworks/compliance/cra/essential_requirements</code> — 1 file(s)</summary>

- `cra_essential_requirements.rego`

</details>

<details><summary><code>frameworks/compliance/cra/foss_exclusion</code> — 1 file(s)</summary>

- `cra_foss_exclusion.rego`

</details>

<details><summary><code>frameworks/compliance/cra/importer_obligations</code> — 1 file(s)</summary>

- `cra_importer_obligations.rego`

</details>

<details><summary><code>frameworks/compliance/cra/incident_reporting</code> — 1 file(s)</summary>

- `cra_incident_reporting.rego`

</details>

<details><summary><code>frameworks/compliance/cra/manufacturer_obligations</code> — 1 file(s)</summary>

- `cra_manufacturer_obligations.rego`

</details>

<details><summary><code>frameworks/compliance/cra/online_marketplace</code> — 1 file(s)</summary>

- `cra_online_marketplace.rego`

</details>

<details><summary><code>frameworks/compliance/cra/oss_steward</code> — 1 file(s)</summary>

- `cra_oss_steward.rego`

</details>

<details><summary><code>frameworks/compliance/cra/substantial_modification</code> — 1 file(s)</summary>

- `cra_substantial_modification.rego`

</details>

<details><summary><code>frameworks/compliance/cra/supply_chain_evidence</code> — 1 file(s)</summary>

- `cra_supply_chain_evidence.rego`

</details>

<details><summary><code>frameworks/compliance/cra/technical_documentation</code> — 1 file(s)</summary>

- `cra_technical_documentation.rego`

</details>

<details><summary><code>frameworks/compliance/cra/user_information</code> — 1 file(s)</summary>

- `cra_user_information.rego`

</details>

<details><summary><code>frameworks/compliance/cra/vulnerability_handling</code> — 1 file(s)</summary>

- `cra_vulnerability_handling.rego`

</details>

<details><summary><code>frameworks/compliance/ncsc_caf</code> — 7 file(s)</summary>

- `caf_a3_asset_management.rego`
- `caf_b2_identity_access.rego`
- `caf_b3_data_security.rego`
- `caf_b4_system_security.rego`
- `caf_b5_resilience.rego`
- `caf_c1_security_monitoring.rego`
- `caf_d1_response_recovery.rego`

</details>

<details><summary><code>frameworks/critical_infrastructure/ami/nist_ir_7628</code> — 6 file(s)</summary>

- `nist_ir7628_access_control.rego`
- `nist_ir7628_audit.rego`
- `nist_ir7628_config_management.rego`
- `nist_ir7628_identification_auth.rego`
- `nist_ir7628_incident_response.rego`
- `nist_ir7628_system_comms.rego`

</details>

<details><summary><code>frameworks/critical_infrastructure/iec_62443</code> — 11 file(s)</summary>

- `fr1_identification_authentication.rego`
- `fr2_use_control.rego`
- `fr3_system_integrity.rego`
- `fr4_data_confidentiality.rego`
- `fr5_restricted_data_flow.rego`
- `fr6_timely_response.rego`
- `fr7_resource_availability.rego`
- `part2_patch_management.rego`
- `part2_security_management.rego`
- `part2_service_provider.rego`
- `part3_risk_assessment.rego`

</details>

<details><summary><code>frameworks/critical_infrastructure/nerc_cip</code> — 14 file(s)</summary>

- `cip_002_asset_identification.rego`
- `cip_003_security_management.rego`
- `cip_004_personnel_training.rego`
- `cip_005_electronic_security.rego`
- `cip_006_physical_security.rego`
- `cip_007_systems_security.rego`
- `cip_008_incident_response.rego`
- `cip_009_recovery_plans.rego`
- `cip_010_configuration_management.rego`
- `cip_011_information_protection.rego`
- `cip_012_communications.rego`
- `cip_013_supply_chain.rego`
- `cip_014_physical_security_transmission.rego`
- `nerc_cip_simplified.rego`

</details>

<details><summary><code>frameworks/critical_infrastructure/tsa_pipeline</code> — 12 file(s)</summary>

- `sd01_cybersecurity_coordinator.rego`
- `sd01_incident_reporting.rego`
- `sd01_vulnerability_assessment.rego`
- `sd02_access_control.rego`
- `sd02_assessment_plan.rego`
- `sd02_continuous_monitoring.rego`
- `sd02_critical_cyber_systems.rego`
- `sd02_implementation_plan.rego`
- `sd02_incident_response_plan.rego`
- `sd02_network_segmentation.rego`
- `sd02_patch_management.rego`
- `sd02_records.rego`

</details>

<details><summary><code>frameworks/federal/cmmc</code> — 14 file(s)</summary>

- `cmmc_access_control.rego`
- `cmmc_audit_accountability.rego`
- `cmmc_awareness_training.rego`
- `cmmc_configuration_management.rego`
- `cmmc_identification_authentication.rego`
- `cmmc_incident_response.rego`
- `cmmc_maintenance.rego`
- `cmmc_media_protection.rego`
- `cmmc_personnel_security.rego`
- `cmmc_physical_protection.rego`
- `cmmc_risk_assessment.rego`
- `cmmc_security_assessment.rego`
- `cmmc_system_communications_protection.rego`
- `cmmc_system_information_integrity.rego`

</details>

<details><summary><code>frameworks/federal/fedramp</code> — 1 file(s)</summary>

- `fedramp_main.rego`

</details>

<details><summary><code>frameworks/federal/fisma</code> — 3 file(s)</summary>

- `authority_to_operate.rego`
- `continuous_monitoring.rego`
- `system_security_plan.rego`

</details>

<details><summary><code>frameworks/federal/nist/ai_rmf</code> — 1 file(s)</summary>

- `nist_ai_rmf.rego`

</details>

<details><summary><code>frameworks/federal/nist/cybersecurity_framework_2.0/detect</code> — 1 file(s)</summary>

- `detect.rego`

</details>

<details><summary><code>frameworks/federal/nist/cybersecurity_framework_2.0/govern</code> — 1 file(s)</summary>

- `governance.rego`

</details>

<details><summary><code>frameworks/federal/nist/cybersecurity_framework_2.0/identify</code> — 1 file(s)</summary>

- `identify.rego`

</details>

<details><summary><code>frameworks/federal/nist/cybersecurity_framework_2.0/protect</code> — 1 file(s)</summary>

- `access_control.rego`

</details>

<details><summary><code>frameworks/federal/nist/cybersecurity_framework_2.0/recover</code> — 1 file(s)</summary>

- `recover.rego`

</details>

<details><summary><code>frameworks/federal/nist/cybersecurity_framework_2.0/respond</code> — 1 file(s)</summary>

- `respond.rego`

</details>

<details><summary><code>frameworks/federal/nist/risk_management_framework/categorize</code> — 1 file(s)</summary>

- `system_categorization.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/access_control</code> — 1 file(s)</summary>

- `cui_access_control.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/audit_accountability</code> — 1 file(s)</summary>

- `nist_800_171_au.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/awareness_training</code> — 1 file(s)</summary>

- `nist_800_171_at.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/configuration_management</code> — 1 file(s)</summary>

- `nist_800_171_cm.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/identification_authentication</code> — 1 file(s)</summary>

- `nist_800_171_ia.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/incident_response</code> — 1 file(s)</summary>

- `nist_800_171_ir.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/maintenance</code> — 1 file(s)</summary>

- `nist_800_171_ma.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/media_protection</code> — 1 file(s)</summary>

- `nist_800_171_mp.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/personnel_security</code> — 1 file(s)</summary>

- `nist_800_171_ps.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/physical_protection</code> — 1 file(s)</summary>

- `nist_800_171_pe.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/risk_assessment</code> — 1 file(s)</summary>

- `nist_800_171_ra.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/security_assessment</code> — 1 file(s)</summary>

- `nist_800_171_ca.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/system_communications</code> — 1 file(s)</summary>

- `nist_800_171_sc.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_171/system_information</code> — 1 file(s)</summary>

- `nist_800_171_si.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_53/access_control</code> — 1 file(s)</summary>

- `ac_controls.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_53/audit_accountability</code> — 1 file(s)</summary>

- `au_controls.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_53/configuration_management</code> — 1 file(s)</summary>

- `cm_controls.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_53/identification_authentication</code> — 1 file(s)</summary>

- `ia_controls.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_53/incident_response</code> — 1 file(s)</summary>

- `ir_controls.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_53/system_communications</code> — 1 file(s)</summary>

- `sc_controls.rego`

</details>

<details><summary><code>frameworks/federal/nist/sp_800_53/system_information_integrity</code> — 1 file(s)</summary>

- `si_controls.rego`

</details>

<details><summary><code>frameworks/federal/nist_ssdf</code> — 4 file(s)</summary>

- `po_prepare_organization.rego`
- `ps_protect_software.rego`
- `pw_produce_secured_software.rego`
- `rv_respond_vulnerabilities.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/access_control</code> — 2 file(s)</summary>

- `requirement_7.rego`
- `requirement_8.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/data_protection</code> — 2 file(s)</summary>

- `requirement_3.rego`
- `requirement_4.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/governance</code> — 1 file(s)</summary>

- `requirement_12.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/logging_monitoring</code> — 1 file(s)</summary>

- `requirement_10.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/malware_protection</code> — 1 file(s)</summary>

- `requirement_5.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/network_security</code> — 1 file(s)</summary>

- `requirement_1.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/physical_security</code> — 1 file(s)</summary>

- `requirement_9.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/secure_development</code> — 1 file(s)</summary>

- `requirement_6.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/security_testing</code> — 1 file(s)</summary>

- `requirement_11.rego`

</details>

<details><summary><code>frameworks/financial/pci_dss/system_hardening</code> — 1 file(s)</summary>

- `requirement_2.rego`

</details>

<details><summary><code>frameworks/financial/sox</code> — 1 file(s)</summary>

- `sox_simplified.rego`

</details>

<details><summary><code>frameworks/financial/sox/application_controls</code> — 1 file(s)</summary>

- `financial_application_controls.rego`

</details>

<details><summary><code>frameworks/financial/sox/itgc</code> — 1 file(s)</summary>

- `it_general_controls.rego`

</details>

<details><summary><code>frameworks/management/corporate</code> — 4 file(s)</summary>

- `access_control.rego`
- `backup_policy.rego`
- `environment_controls.rego`
- `password_policy.rego`

</details>

<details><summary><code>frameworks/management/csa_ccm</code> — 16 file(s)</summary>

- `csa_ccm_application_security.rego`
- `csa_ccm_audit_assurance.rego`
- `csa_ccm_business_continuity.rego`
- `csa_ccm_change_control.rego`
- `csa_ccm_cryptography.rego`
- `csa_ccm_data_security.rego`
- `csa_ccm_endpoint_management.rego`
- `csa_ccm_governance.rego`
- `csa_ccm_human_resources.rego`
- `csa_ccm_identity_access.rego`
- `csa_ccm_incident_management.rego`
- `csa_ccm_infrastructure.rego`
- `csa_ccm_interoperability.rego`
- `csa_ccm_logging_monitoring.rego`
- `csa_ccm_supply_chain.rego`
- `csa_ccm_threat_vulnerability.rego`

</details>

<details><summary><code>frameworks/management/iso27001/access_control</code> — 1 file(s)</summary>

- `access_control.rego`

</details>

<details><summary><code>frameworks/management/iso27001/communications_security</code> — 1 file(s)</summary>

- `communications_security.rego`

</details>

<details><summary><code>frameworks/management/iso27001/cryptography</code> — 1 file(s)</summary>

- `cryptography.rego`

</details>

<details><summary><code>frameworks/management/iso27001/operations_security</code> — 1 file(s)</summary>

- `operations_security.rego`

</details>

<details><summary><code>frameworks/management/iso27001/system_acquisition_maintenance</code> — 1 file(s)</summary>

- `system_acquisition_maintenance.rego`

</details>

<details><summary><code>frameworks/management/soc2</code> — 2 file(s)</summary>

- `soc2_assessment.rego`
- `soc2_main.rego`

</details>

<details><summary><code>frameworks/management/soc2/availability</code> — 1 file(s)</summary>

- `system_availability.rego`

</details>

<details><summary><code>frameworks/management/soc2/confidentiality</code> — 1 file(s)</summary>

- `data_confidentiality.rego`

</details>

<details><summary><code>frameworks/management/soc2/infrastructure/applications_services</code> — 1 file(s)</summary>

- `applications_services.rego`

</details>

<details><summary><code>frameworks/management/soc2/infrastructure/network</code> — 1 file(s)</summary>

- `network_infrastructure.rego`

</details>

<details><summary><code>frameworks/management/soc2/infrastructure/security</code> — 1 file(s)</summary>

- `security_infrastructure.rego`

</details>

<details><summary><code>frameworks/management/soc2/infrastructure/storage</code> — 1 file(s)</summary>

- `storage_infrastructure.rego`

</details>

<details><summary><code>frameworks/management/soc2/infrastructure/systems</code> — 1 file(s)</summary>

- `systems_infrastructure.rego`

</details>

<details><summary><code>frameworks/management/soc2/privacy</code> — 1 file(s)</summary>

- `data_privacy.rego`

</details>

<details><summary><code>frameworks/management/soc2/processing_integrity</code> — 1 file(s)</summary>

- `data_processing.rego`

</details>

<details><summary><code>frameworks/management/soc2/security</code> — 1 file(s)</summary>

- `access_controls.rego`

</details>

<details><summary><code>frameworks/management/technical_debt</code> — 1 file(s)</summary>

- `debt_scoring.rego`

</details>

<details><summary><code>frameworks/privacy/ccpa</code> — 4 file(s)</summary>

- `ccpa_business_obligations.rego`
- `ccpa_consumer_rights.rego`
- `ccpa_data_practices.rego`
- `ccpa_sensitive_data.rego`

</details>

<details><summary><code>frameworks/privacy/gdpr</code> — 4 file(s)</summary>

- `gdpr_compliance.rego`
- `gdpr_controller_processor.rego`
- `gdpr_cookies_tracking.rego`
- `gdpr_data_transfers.rego`

</details>

<details><summary><code>frameworks/privacy/hipaa</code> — 7 file(s)</summary>

- `hipaa_access_control.rego`
- `hipaa_audit_controls.rego`
- `hipaa_authentication.rego`
- `hipaa_hitech.rego`
- `hipaa_integrity.rego`
- `hipaa_privacy_rule.rego`
- `hipaa_transmission_security.rego`

</details>

<details><summary><code>frameworks/privacy/iso27701</code> — 4 file(s)</summary>

- `iso27701_data_subject_rights.rego`
- `iso27701_pii_controller.rego`
- `iso27701_pii_processor.rego`
- `iso27701_pims_requirements.rego`

</details>

<details><summary><code>frameworks/sovereignty/digital_sovereignty</code> — 11 file(s)</summary>

- `ai_sovereignty.rego`
- `breach_notification_sovereignty.rego`
- `cryptographic_sovereignty.rego`
- `cyber_resilience_sovereignty.rego`
- `data_residency.rego`
- `dora_sovereignty.rego`
- `geopolitical_sovereignty.rego`
- `infrastructure_sovereignty.rego`
- `network_sovereignty.rego`
- `operational_sovereignty.rego`
- `software_sovereignty.rego`

</details>

<details><summary><code>governance/ai</code> — 3 file(s)</summary>

- `action_classification.rego`
- `authorization.rego`
- `context_validation.rego`

</details>

<details><summary><code>governance/eu_ai_act</code> — 5 file(s)</summary>

- `eu_ai_act_governance.rego`
- `eu_ai_act_gpai.rego`
- `eu_ai_act_high_risk.rego`
- `eu_ai_act_prohibited.rego`
- `eu_ai_act_transparency.rego`

</details>

<details><summary><code>governance/geisa</code> — 6 file(s)</summary>

- `geisa_adm.rego`
- `geisa_api.rego`
- `geisa_compliance.rego`
- `geisa_lee.rego`
- `geisa_manifest_validation.rego`
- `geisa_vee.rego`

</details>

