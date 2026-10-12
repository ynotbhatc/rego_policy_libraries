# Test generation — what each untested module was proven to do

`scripts/gen_tests.py` wrote a smoke test for every module without one and kept only the expectations each module meets. Suite: **3345 tests pass**.

| expectation | asserted by | not met by |
|---|---|---|
| module evaluates on empty input | 554 | 0 |
| report is an object on empty input | 342 | 67 |
| report is not compliant on empty input (fail-closed) | 301 | 111 |
| violations non-empty on empty input | 281 | 72 |

## Modules that are compliant on empty input (fail-open) — findings, not hidden

- `benchmarks/cis/amazon_linux_2023/file_permissions_validation.rego`
- `benchmarks/cis/amazon_linux_2023/filesystem_validation.rego`
- `benchmarks/cis/amazon_linux_2023/logging_validation.rego`
- `benchmarks/cis/amazon_linux_2023/network_validation.rego`
- `benchmarks/cis/amazon_linux_2023/service_validation.rego`
- `benchmarks/cis/amazon_linux_2023/ssh_validation.rego`
- `benchmarks/cis/amazon_linux_2023/user_group_validation.rego`
- `benchmarks/cis/databases/oracle_legacy/modules/database_parameters.rego`
- `benchmarks/cis/databases/oracle_legacy/modules/installation_patches.rego`
- `benchmarks/cis/databases/oracle_legacy/modules/listener_configuration.rego`
- `benchmarks/cis/databases/oracle_legacy/modules/user_account_management.rego`
- `benchmarks/cis/debian_11/apparmor_validation.rego`
- `benchmarks/cis/debian_11/file_permissions_validation.rego`
- `benchmarks/cis/debian_11/filesystem_validation.rego`
- `benchmarks/cis/debian_11/logging_validation.rego`
- `benchmarks/cis/debian_11/network_validation.rego`
- `benchmarks/cis/debian_11/ssh_validation.rego`
- `benchmarks/cis/debian_11/user_group_validation.rego`
- `benchmarks/cis/os/linux/rhel_9_legacy/modules/ssh_validation.rego`
- `benchmarks/cis/rhel_8/file_permissions_validation.rego`
- `benchmarks/cis/rhel_8/filesystem_validation.rego`
- `benchmarks/cis/rhel_8/logging_validation.rego`
- `benchmarks/cis/rhel_8/network_validation.rego`
- `benchmarks/cis/rhel_8/ssh_validation.rego`
- `benchmarks/cis/rhel_8/user_group_validation.rego`
- `benchmarks/cis/rhel_9/authorized_keys_validation.rego`
- `benchmarks/cis/rhel_9/file_permissions_validation.rego`
- `benchmarks/cis/rhel_9/filesystem_validation.rego`
- `benchmarks/cis/rhel_9/logging_validation.rego`
- `benchmarks/cis/rhel_9/network_validation.rego`
- `benchmarks/cis/rhel_9/service_validation.rego`
- `benchmarks/cis/rhel_9/ssh_validation.rego`
- `benchmarks/cis/rhel_9/storage_encryption_validation.rego`
- `benchmarks/cis/rhel_9/user_group_validation.rego`
- `benchmarks/cis/rocky_linux_8/file_permissions_validation.rego`
- `benchmarks/cis/rocky_linux_8/filesystem_validation.rego`
- `benchmarks/cis/rocky_linux_8/logging_validation.rego`
- `benchmarks/cis/rocky_linux_8/network_validation.rego`
- `benchmarks/cis/rocky_linux_8/ssh_validation.rego`
- `benchmarks/cis/rocky_linux_8/user_group_validation.rego`
- `benchmarks/cis/rocky_linux_9/file_permissions_validation.rego`
- `benchmarks/cis/rocky_linux_9/filesystem_validation.rego`
- `benchmarks/cis/rocky_linux_9/logging_validation.rego`
- `benchmarks/cis/rocky_linux_9/network_validation.rego`
- `benchmarks/cis/rocky_linux_9/ssh_validation.rego`
- `benchmarks/cis/rocky_linux_9/user_group_validation.rego`
- `benchmarks/cis/ubuntu_20_04/apparmor_validation.rego`
- `benchmarks/cis/ubuntu_20_04/file_permissions_validation.rego`
- `benchmarks/cis/ubuntu_20_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_20_04/logging_validation.rego`
- `benchmarks/cis/ubuntu_20_04/network_validation.rego`
- `benchmarks/cis/ubuntu_20_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_20_04/user_group_validation.rego`
- `benchmarks/cis/ubuntu_22_04/apparmor_validation.rego`
- `benchmarks/cis/ubuntu_22_04/file_permissions_validation.rego`
- `benchmarks/cis/ubuntu_22_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_22_04/logging_validation.rego`
- `benchmarks/cis/ubuntu_22_04/network_validation.rego`
- `benchmarks/cis/ubuntu_22_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_22_04/user_group_validation.rego`
- `benchmarks/cis/ubuntu_24_04/apparmor_validation.rego`
- `benchmarks/cis/ubuntu_24_04/file_permissions_validation.rego`
- `benchmarks/cis/ubuntu_24_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_24_04/logging_validation.rego`
- `benchmarks/cis/ubuntu_24_04/network_validation.rego`
- `benchmarks/cis/ubuntu_24_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_24_04/user_group_validation.rego`
- `benchmarks/cis/windows_server_2019_modular/bitlocker_validation.rego`
- `benchmarks/cis/windows_server_2019_modular/event_log_validation.rego`
- `benchmarks/cis/windows_server_2019_modular/system_services_validation.rego`
- `benchmarks/cis/windows_server_2019_modular/windows_defender_validation.rego`
- `benchmarks/cis/windows_server_2022_modular/bitlocker_validation.rego`
- `benchmarks/cis/windows_server_2022_modular/event_log_validation.rego`
- `benchmarks/cis/windows_server_2022_modular/system_services_validation.rego`
- `benchmarks/cis/windows_server_2022_modular/windows_defender_validation.rego`
- `benchmarks/stig/rhel_8/file_permissions.rego`
- `benchmarks/stig/rhel_8/services.rego`
- `benchmarks/stig/rhel_9/file_permissions.rego`
- `benchmarks/stig/rhel_9/services.rego`
- `benchmarks/supply_chain/coverage/coverage.rego`
- `enforcement/cicd/cicd_pipeline.rego`
- `enforcement/git/playbook_documentation.rego`
- `enforcement/kubernetes/kubernetes_admission.rego`
- `frameworks/compliance/cra/authorised_representative/cra_authorised_representative.rego`
- `frameworks/compliance/cra/foss_exclusion/cra_foss_exclusion.rego`
- `frameworks/compliance/cra/online_marketplace/cra_online_marketplace.rego`
- `frameworks/compliance/cra/oss_steward/cra_oss_steward.rego`
- `frameworks/critical_infrastructure/ami/device_compliance/ami_device_compliance.rego`
- `frameworks/critical_infrastructure/iec_62443/fr4_data_confidentiality.rego`
- `frameworks/critical_infrastructure/iec_62443/part2_service_provider.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_002_asset_identification.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_003_security_management.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_004_personnel_training.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_005_electronic_security.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_006_physical_security.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_007_systems_security.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_008_incident_response.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_009_recovery_plans.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_010_configuration_management.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_011_information_protection.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_012_communications.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_013_supply_chain.rego`
- `frameworks/critical_infrastructure/nerc_cip/cip_014_physical_security_transmission.rego`
- `frameworks/federal/cmmc/cmmc_configuration_management.rego`
- `frameworks/federal/cmmc/cmmc_incident_response.rego`
- `governance/eu_ai_act/eu_ai_act_transparency.rego`
- `governance/finops/finops_tagging.rego`
- `governance/geisa/geisa_adm.rego`
- `governance/geisa/geisa_compliance.rego`
- `governance/geisa/geisa_lee.rego`
- `governance/geisa/geisa_vee.rego`

## Modules whose violations are empty on empty input

Often by design (the module iterates a list that is absent), sometimes fail-open; each deserves a look.

- `benchmarks/cis/amazon_linux_2023/filesystem_validation.rego`
- `benchmarks/cis/amazon_linux_2023/network_validation.rego`
- `benchmarks/cis/amazon_linux_2023/pam_validation.rego`
- `benchmarks/cis/amazon_linux_2023/ssh_validation.rego`
- `benchmarks/cis/amazon_linux_2023/user_group_validation.rego`
- `benchmarks/cis/databases/oracle_legacy/modules/user_account_management.rego`
- `benchmarks/cis/debian_11/filesystem_validation.rego`
- `benchmarks/cis/debian_11/network_validation.rego`
- `benchmarks/cis/debian_11/pam_validation.rego`
- `benchmarks/cis/debian_11/ssh_validation.rego`
- `benchmarks/cis/debian_11/user_group_validation.rego`
- `benchmarks/cis/gcp/cis_gcp_foundations.rego`
- `benchmarks/cis/nginx/cis_nginx_1_20.rego`
- `benchmarks/cis/openshift/cis_openshift_4.rego`
- `benchmarks/cis/os/linux/rhel_9_legacy/modules/pam_validation.rego`
- `benchmarks/cis/os/linux/rhel_9_legacy/modules/ssh_validation.rego`
- `benchmarks/cis/rhel_8/filesystem_validation.rego`
- `benchmarks/cis/rhel_8/network_validation.rego`
- `benchmarks/cis/rhel_8/pam_validation.rego`
- `benchmarks/cis/rhel_8/ssh_validation.rego`
- `benchmarks/cis/rhel_8/user_group_validation.rego`
- `benchmarks/cis/rhel_9/authorized_keys_validation.rego`
- `benchmarks/cis/rhel_9/filesystem_validation.rego`
- `benchmarks/cis/rhel_9/network_validation.rego`
- `benchmarks/cis/rhel_9/pam_validation.rego`
- `benchmarks/cis/rhel_9/ssh_validation.rego`
- `benchmarks/cis/rhel_9/storage_encryption_validation.rego`
- `benchmarks/cis/rhel_9/user_group_validation.rego`
- `benchmarks/cis/rocky_linux_8/filesystem_validation.rego`
- `benchmarks/cis/rocky_linux_8/network_validation.rego`
- `benchmarks/cis/rocky_linux_8/pam_validation.rego`
- `benchmarks/cis/rocky_linux_8/ssh_validation.rego`
- `benchmarks/cis/rocky_linux_8/user_group_validation.rego`
- `benchmarks/cis/rocky_linux_9/filesystem_validation.rego`
- `benchmarks/cis/rocky_linux_9/network_validation.rego`
- `benchmarks/cis/rocky_linux_9/pam_validation.rego`
- `benchmarks/cis/rocky_linux_9/ssh_validation.rego`
- `benchmarks/cis/rocky_linux_9/user_group_validation.rego`
- `benchmarks/cis/ubuntu_20_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_20_04/network_validation.rego`
- `benchmarks/cis/ubuntu_20_04/pam_validation.rego`
- `benchmarks/cis/ubuntu_20_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_20_04/user_group_validation.rego`
- `benchmarks/cis/ubuntu_22_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_22_04/network_validation.rego`
- `benchmarks/cis/ubuntu_22_04/pam_validation.rego`
- `benchmarks/cis/ubuntu_22_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_22_04/user_group_validation.rego`
- `benchmarks/cis/ubuntu_24_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_24_04/network_validation.rego`
- `benchmarks/cis/ubuntu_24_04/pam_validation.rego`
- `benchmarks/cis/ubuntu_24_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_24_04/user_group_validation.rego`
- `benchmarks/cis/vmware/esxi/cis_esxi_8.rego`
- `benchmarks/cis/vmware/vcenter/cis_vcenter_8.rego`
- `benchmarks/cis/windows_server_2019_modular/system_services_validation.rego`
- `benchmarks/cis/windows_server_2022_modular/system_services_validation.rego`
- `benchmarks/stig/rhel_8/services.rego`
- `benchmarks/stig/rhel_9/services.rego`
- `enforcement/cicd/cicd_pipeline.rego`
- `enforcement/kubernetes/kubernetes_admission.rego`
- `enforcement/terraform/sentinel_terraform.rego`
- `frameworks/critical_infrastructure/iec_62443/fr4_data_confidentiality.rego`
- `frameworks/critical_infrastructure/iec_62443/part2_service_provider.rego`
- `frameworks/federal/cmmc/cmmc_configuration_management.rego`
- `frameworks/federal/cmmc/cmmc_incident_response.rego`
- `governance/eu_ai_act/eu_ai_act_transparency.rego`
- `governance/finops/finops_tagging.rego`
- `governance/geisa/geisa_adm.rego`
- `governance/geisa/geisa_lee.rego`
- `governance/geisa/geisa_vee.rego`
- `threat_detection/crypto_mining/crypto_miner_detection.rego`

## Modules with a runtime error on empty input (defects; no test written)

