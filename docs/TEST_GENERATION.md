# Test generation — what each untested module was proven to do

`scripts/gen_tests.py` wrote a smoke test for every module without one and kept only the expectations each module meets. Suite: **3514 tests pass**.

| expectation | asserted by | not met by |
|---|---|---|
| module evaluates on empty input | 554 | 0 |
| report is an object on empty input | 406 | 1 |
| report is not compliant on empty input (fail-closed) | 373 | 34 |
| violations non-empty on empty input | 314 | 39 |

## Modules that report compliant on empty input

Classified by the fail-closed guard the coverage scan measures (`custom.coverage.guard`):

### guarded by their orchestrator (by design for sectioned benchmarks: the orchestrator is fail-closed and references them) (23)

- `benchmarks/cis/debian_11/filesystem_validation.rego`
- `benchmarks/cis/debian_11/network_validation.rego`
- `benchmarks/cis/debian_11/ssh_validation.rego`
- `benchmarks/cis/debian_11/user_group_validation.rego`
- `benchmarks/cis/ubuntu_20_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_20_04/network_validation.rego`
- `benchmarks/cis/ubuntu_20_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_20_04/user_group_validation.rego`
- `benchmarks/cis/ubuntu_22_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_22_04/network_validation.rego`
- `benchmarks/cis/ubuntu_22_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_22_04/user_group_validation.rego`
- `benchmarks/cis/ubuntu_24_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_24_04/network_validation.rego`
- `benchmarks/cis/ubuntu_24_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_24_04/user_group_validation.rego`
- `benchmarks/stig/rhel_8/services.rego`
- `benchmarks/stig/rhel_9/services.rego`
- `frameworks/compliance/cra/authorised_representative/cra_authorised_representative.rego`
- `frameworks/compliance/cra/foss_exclusion/cra_foss_exclusion.rego`
- `frameworks/compliance/cra/online_marketplace/cra_online_marketplace.rego`
- `frameworks/compliance/cra/oss_steward/cra_oss_steward.rego`
- `governance/eu_ai_act/eu_ai_act_transparency.rego`

### **unguarded — fail-open; the work queue for the library's fail-closed rule** (6)

- `benchmarks/cis/amazon_linux_2023/filesystem_validation.rego`
- `benchmarks/cis/amazon_linux_2023/network_validation.rego`
- `benchmarks/cis/databases/oracle_legacy/modules/user_account_management.rego`
- `benchmarks/cis/rhel_8/network_validation.rego`
- `benchmarks/cis/rocky_linux_8/network_validation.rego`
- `benchmarks/cis/rocky_linux_9/network_validation.rego`

### report defined and compliant on empty input while the module itself emits violations — the report's `compliant` is computed from a subset of the checks; a defect in the report literal (2)

- `benchmarks/stig/rhel_8/file_permissions.rego`
- `benchmarks/stig/rhel_9/file_permissions.rego`

### no report or violations rule (2)

- `enforcement/cicd/cicd_pipeline.rego`
- `enforcement/kubernetes/kubernetes_admission.rego`

## Modules whose report is undefined on empty input

The report rule itself does not evaluate without facts (Rego v1 undefined, the `{}` collapse the library's contract forbids): a consumer gets nothing, not a non-compliant report. Each is a defect against the fail-closed contract.

- `enforcement/git/playbook_documentation.rego`

## Modules whose violations are empty on empty input

Often by design (the module iterates a list that is absent); classified the same way.

### guard = orchestrator (19)

- `benchmarks/cis/debian_11/filesystem_validation.rego`
- `benchmarks/cis/debian_11/network_validation.rego`
- `benchmarks/cis/debian_11/ssh_validation.rego`
- `benchmarks/cis/debian_11/user_group_validation.rego`
- `benchmarks/cis/ubuntu_20_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_20_04/network_validation.rego`
- `benchmarks/cis/ubuntu_20_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_20_04/user_group_validation.rego`
- `benchmarks/cis/ubuntu_22_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_22_04/network_validation.rego`
- `benchmarks/cis/ubuntu_22_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_22_04/user_group_validation.rego`
- `benchmarks/cis/ubuntu_24_04/filesystem_validation.rego`
- `benchmarks/cis/ubuntu_24_04/network_validation.rego`
- `benchmarks/cis/ubuntu_24_04/ssh_validation.rego`
- `benchmarks/cis/ubuntu_24_04/user_group_validation.rego`
- `benchmarks/stig/rhel_8/services.rego`
- `benchmarks/stig/rhel_9/services.rego`
- `governance/eu_ai_act/eu_ai_act_transparency.rego`

### guard = none (14)

- `benchmarks/cis/amazon_linux_2023/filesystem_validation.rego`
- `benchmarks/cis/amazon_linux_2023/network_validation.rego`
- `benchmarks/cis/amazon_linux_2023/user_group_validation.rego`
- `benchmarks/cis/databases/oracle_legacy/modules/user_account_management.rego`
- `benchmarks/cis/gcp/cis_gcp_foundations.rego`
- `benchmarks/cis/nginx/cis_nginx_1_20.rego`
- `benchmarks/cis/openshift/cis_openshift_4.rego`
- `benchmarks/cis/os/linux/rhel_9_legacy/modules/pam_validation.rego`
- `benchmarks/cis/rhel_8/network_validation.rego`
- `benchmarks/cis/rocky_linux_8/network_validation.rego`
- `benchmarks/cis/rocky_linux_9/network_validation.rego`
- `benchmarks/cis/vmware/esxi/cis_esxi_8.rego`
- `benchmarks/cis/vmware/vcenter/cis_vcenter_8.rego`
- `threat_detection/crypto_mining/crypto_miner_detection.rego`

### guard = self (3)

- `benchmarks/cis/rhel_8/filesystem_validation.rego`
- `benchmarks/cis/windows_server_2019_modular/system_services_validation.rego`
- `benchmarks/cis/windows_server_2022_modular/system_services_validation.rego`

### guard = n/a (3)

- `enforcement/cicd/cicd_pipeline.rego`
- `enforcement/kubernetes/kubernetes_admission.rego`
- `enforcement/terraform/sentinel_terraform.rego`


## Modules with a runtime error on empty input (defects; no test written)

