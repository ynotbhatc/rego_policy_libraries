# METADATA
# title: "Framework keys the product addresses at /v1/data/<key>/main/compliance_report"
# custom:
#   class: governance
#   framework: framework_keys
#   source: internal
#   domains: [library]
#   coverage:
#     checks: 0
#     cited: 0
#     density: unrecognised
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package framework_keys

import rego.v1

# Every key the compliance product's opa_framework_map and framework catalog can evaluate. Each
# must resolve to data.<key>.main.compliance_report, defined and non-compliant on empty input.
keys := {
	"ai_governance", "ami_device", "ami_headend", "ami_nist_ir7628", "ccpa", "cfr_part_11",
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
