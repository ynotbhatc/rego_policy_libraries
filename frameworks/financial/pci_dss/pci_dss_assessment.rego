# Consumer endpoint for the compliance-repo pci_dss_compliance role.
# The role queries POST /v1/data/pci_dss/pci_dss_assessment and reads
# .compliant, .score, and .requirement_results off the response.
#
# This lives in the bare `pci_dss` package (NOT pci_dss.main) so it resolves at
# data.pci_dss.pci_dss_assessment — the exact path the playbook queries. Logic
# is delegated to pci_dss.main; score = % of the 12 PCI DSS requirements passing.
package pci_dss

import rego.v1

import data.pci_dss.main

pci_dss_assessment := {
	"framework": "PCI DSS v4.0",
	"compliant": main.overall_pci_dss_compliant,
	"score": round((100 * main.requirements_passing) / 12),
	"requirements_passing": main.requirements_passing,
	"total_requirements": 12,
	"requirement_results": {
		"req_1_network_security": main.requirement_1_compliant,
		"req_2_system_hardening": main.requirement_2_compliant,
		"req_3_stored_data": main.requirement_3_compliant,
		"req_4_transmission_security": main.requirement_4_compliant,
		"req_5_malware_protection": main.requirement_5_compliant,
		"req_6_secure_development": main.requirement_6_compliant,
		"req_7_access_restriction": main.requirement_7_compliant,
		"req_8_authentication": main.requirement_8_compliant,
		"req_9_physical_access": main.requirement_9_compliant,
		"req_10_logging_monitoring": main.requirement_10_compliant,
		"req_11_security_testing": main.requirement_11_compliant,
		"req_12_governance": main.requirement_12_compliant,
	},
}
