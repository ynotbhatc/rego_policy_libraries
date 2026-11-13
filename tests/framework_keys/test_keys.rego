package framework_keys_test

import rego.v1

# Every key the compliance product's opa_framework_map and framework catalog can evaluate.
keys := {
	"ai_governance", "ami_device", "ami_headend", "ami_nist_ir7628", "as9100d", "ccpa", "cfr_part_11",
	"cis_aks", "cis_amazon_linux_2023", "cis_aws", "cis_azure", "cis_debian_11", "cis_docker",
	"cis_eks", "cis_gcp", "cis_gke", "cis_kubernetes", "cis_openshift", "cis_pfsense", "cis_rhel10",
	"cis_rhel8", "cis_rhel9", "cis_rocky_linux_8", "cis_rocky_linux_9", "cis_ubuntu_2004",
	"cis_ubuntu_2204", "cis_ubuntu_2404", "cis_vyos", "cis_windows_2019", "cis_windows_2022",
	"cisa_cpg", "cmmc", "cobit", "coppa", "cra", "crypto_miner_detection", "csa_ccm",
	"digital_sovereignty", "dora", "eu_ai_act", "fedramp", "ferpa", "fisma", "gdpr", "glba", "hipaa",
	"hitrust", "iec_62443", "iso27001", "iso27701", "iso_42001", "itar", "k8s_pss", "ncsc_caf",
	"nerc_cip", "nis2", "nist_800_171", "nist_800_53", "nist_800_82", "nist_ai_rmf", "nist_csf",
	"nsa_cisa_k8s", "ny_dfs", "pci_dss", "scuba_m365", "sec_cyber", "sentinel_ansible",
	"sentinel_dockerfile", "sentinel_kubernetes", "sentinel_terraform", "soc2", "sox",
	"stig_amazon_linux_2023", "stig_apache_2_4", "stig_cisco_ios_xe_router", "stig_kubernetes",
	"stig_ms_sql_2016", "stig_openshift_4", "stig_postgresql_16", "stig_rhel8", "stig_rhel9",
	"stig_sles_15", "stig_ubuntu_2204", "stig_vsphere_8_esxi", "stig_windows_11",
	"stig_windows_server_2022", "stig_windows_server_2025", "swift_csp", "tisax", "tsa_pipeline",
}

# One test per product key: the entrypoint resolves on empty input, is an object, is not compliant,
# and meets the product contract: a numeric total_controls (the control count, not the finding count),
# a violations list, and a numeric failed_controls that never exceeds total_controls. Findings can
# outnumber controls (fail-closed and input-contract notices are findings, not controls), so the product
# derives passed = total_controls - failed_controls, never total - count(violations). A key that
# collapses to undefined fails its own test, so the failure names the key.

_contract(r) if {
	is_number(r.total_controls)
	_listlike(r.violations)
	is_number(r.failed_controls)
	r.failed_controls >= 0
	r.failed_controls <= r.total_controls
}

_listlike(x) if is_array(x)

_listlike(x) if is_set(x)

test_key_ai_governance if {
	r := data.ai_governance.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_ami_device if {
	r := data.ami_device.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_ami_headend if {
	r := data.ami_headend.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_ami_nist_ir7628 if {
	r := data.ami_nist_ir7628.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_as9100d if {
	r := data.as9100d.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_ccpa if {
	r := data.ccpa.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cfr_part_11 if {
	r := data.cfr_part_11.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_aks if {
	r := data.cis_aks.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_amazon_linux_2023 if {
	r := data.cis_amazon_linux_2023.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_aws if {
	r := data.cis_aws.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_azure if {
	r := data.cis_azure.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_debian_11 if {
	r := data.cis_debian_11.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_docker if {
	r := data.cis_docker.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_eks if {
	r := data.cis_eks.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_gcp if {
	r := data.cis_gcp.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_gke if {
	r := data.cis_gke.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_kubernetes if {
	r := data.cis_kubernetes.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_openshift if {
	r := data.cis_openshift.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_pfsense if {
	r := data.cis_pfsense.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_rhel10 if {
	r := data.cis_rhel10.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_rhel8 if {
	r := data.cis_rhel8.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_rhel9 if {
	r := data.cis_rhel9.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_rocky_linux_8 if {
	r := data.cis_rocky_linux_8.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_rocky_linux_9 if {
	r := data.cis_rocky_linux_9.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_ubuntu_2004 if {
	r := data.cis_ubuntu_2004.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_ubuntu_2204 if {
	r := data.cis_ubuntu_2204.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_ubuntu_2404 if {
	r := data.cis_ubuntu_2404.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_vyos if {
	r := data.cis_vyos.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_windows_2019 if {
	r := data.cis_windows_2019.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cis_windows_2022 if {
	r := data.cis_windows_2022.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cisa_cpg if {
	r := data.cisa_cpg.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cmmc if {
	r := data.cmmc.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cobit if {
	r := data.cobit.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_coppa if {
	r := data.coppa.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_cra if {
	r := data.cra.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_crypto_miner_detection if {
	r := data.crypto_miner_detection.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_csa_ccm if {
	r := data.csa_ccm.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_digital_sovereignty if {
	r := data.digital_sovereignty.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_dora if {
	r := data.dora.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_eu_ai_act if {
	r := data.eu_ai_act.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_fedramp if {
	r := data.fedramp.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_ferpa if {
	r := data.ferpa.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_fisma if {
	r := data.fisma.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_gdpr if {
	r := data.gdpr.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_glba if {
	r := data.glba.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_hipaa if {
	r := data.hipaa.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_hitrust if {
	r := data.hitrust.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_iec_62443 if {
	r := data.iec_62443.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_iso27001 if {
	r := data.iso27001.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_iso27701 if {
	r := data.iso27701.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_iso_42001 if {
	r := data.iso_42001.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_itar if {
	r := data.itar.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_k8s_pss if {
	r := data.k8s_pss.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_ncsc_caf if {
	r := data.ncsc_caf.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_nerc_cip if {
	r := data.nerc_cip.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_nis2 if {
	r := data.nis2.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_nist_800_171 if {
	r := data.nist_800_171.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_nist_800_53 if {
	r := data.nist_800_53.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_nist_800_82 if {
	r := data.nist_800_82.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_nist_ai_rmf if {
	r := data.nist_ai_rmf.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_nist_csf if {
	r := data.nist_csf.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_nsa_cisa_k8s if {
	r := data.nsa_cisa_k8s.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_ny_dfs if {
	r := data.ny_dfs.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_pci_dss if {
	r := data.pci_dss.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_scuba_m365 if {
	r := data.scuba_m365.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_sec_cyber if {
	r := data.sec_cyber.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_sentinel_ansible if {
	r := data.sentinel_ansible.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_sentinel_dockerfile if {
	r := data.sentinel_dockerfile.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_sentinel_kubernetes if {
	r := data.sentinel_kubernetes.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_sentinel_terraform if {
	r := data.sentinel_terraform.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_soc2 if {
	r := data.soc2.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_sox if {
	r := data.sox.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_amazon_linux_2023 if {
	r := data.stig_amazon_linux_2023.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_apache_2_4 if {
	r := data.stig_apache_2_4.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_cisco_ios_xe_router if {
	r := data.stig_cisco_ios_xe_router.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_kubernetes if {
	r := data.stig_kubernetes.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_ms_sql_2016 if {
	r := data.stig_ms_sql_2016.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_openshift_4 if {
	r := data.stig_openshift_4.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_postgresql_16 if {
	r := data.stig_postgresql_16.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_rhel8 if {
	r := data.stig_rhel8.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_rhel9 if {
	r := data.stig_rhel9.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_sles_15 if {
	r := data.stig_sles_15.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_ubuntu_2204 if {
	r := data.stig_ubuntu_2204.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_vsphere_8_esxi if {
	r := data.stig_vsphere_8_esxi.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_windows_11 if {
	r := data.stig_windows_11.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_windows_server_2022 if {
	r := data.stig_windows_server_2022.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_stig_windows_server_2025 if {
	r := data.stig_windows_server_2025.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_swift_csp if {
	r := data.swift_csp.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_tisax if {
	r := data.tisax.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

test_key_tsa_pipeline if {
	r := data.tsa_pipeline.main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	_contract(r)
}

# The key list and this file must stay in step.
test_key_list_is_nonempty if count(keys) > 0

# 2026-11-13 (semantic review): six bridges read `_t.compliant` / `_t.violations`, names their target package
# never defined, so every real finding was dropped and a clean host could never be compliant. With some
# facts supplied (so the fail-closed notice is not added) the bridge must carry the target's findings.
test_bridge_carries_findings_cis_rhel10 if {
	r := data.cis_rhel10.main.compliance_report with input as {"probe": true}
	t := data.cis.rhel_10.main.compliance_report with input as {"probe": true}
	count(t.violations) > 0
	count(r.violations) == count(t.violations)
	r.violation_count == count(t.violations)
}

test_bridge_carries_findings_cis_ubuntu_2004 if {
	r := data.cis_ubuntu_2004.main.compliance_report with input as {"probe": true}
	t := data.cis_ubuntu_20_04.main.compliance_report with input as {"probe": true}
	count(t.violations) > 0
	count(r.violations) == count(t.violations)
	r.violation_count == count(t.violations)
}

test_bridge_carries_findings_cis_ubuntu_2204 if {
	r := data.cis_ubuntu_2204.main.compliance_report with input as {"probe": true}
	t := data.cis_ubuntu_22_04.main.compliance_report with input as {"probe": true}
	count(t.violations) > 0
	count(r.violations) == count(t.violations)
	r.violation_count == count(t.violations)
}

test_bridge_carries_findings_cis_ubuntu_2404 if {
	r := data.cis_ubuntu_2404.main.compliance_report with input as {"probe": true}
	t := data.cis_ubuntu_24_04.main.compliance_report with input as {"probe": true}
	count(t.violations) > 0
	count(r.violations) == count(t.violations)
	r.violation_count == count(t.violations)
}

test_bridge_carries_findings_cis_windows_2019 if {
	r := data.cis_windows_2019.main.compliance_report with input as {"probe": true}
	t := data.cis_windows_server_2019.main.compliance_report with input as {"probe": true}
	count(t.violations) > 0
	count(r.violations) == count(t.violations)
	r.violation_count == count(t.violations)
}

test_bridge_carries_findings_cis_windows_2022 if {
	r := data.cis_windows_2022.main.compliance_report with input as {"probe": true}
	t := data.cis_windows_server_2022.main.compliance_report with input as {"probe": true}
	count(t.violations) > 0
	count(r.violations) == count(t.violations)
	r.violation_count == count(t.violations)
}
