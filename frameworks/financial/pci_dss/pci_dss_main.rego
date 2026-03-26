# PCI DSS v4.0 - Main Aggregation Policy (All 12 Requirements)
# Comprehensive PCI DSS compliance assessment for payment card industry

package pci_dss.main

import rego.v1

import data.pci_dss.access_control.requirement_7
import data.pci_dss.access_control.requirement_8
import data.pci_dss.data_protection.requirement_3
import data.pci_dss.data_protection.requirement_4
import data.pci_dss.governance.requirement_12
import data.pci_dss.logging_monitoring.requirement_10
import data.pci_dss.malware_protection.requirement_5
import data.pci_dss.network_security.requirement_1
import data.pci_dss.physical_security.requirement_9
import data.pci_dss.secure_development.requirement_6
import data.pci_dss.security_testing.requirement_11
import data.pci_dss.system_hardening.requirement_2

# =================================================================
# ALL 12 PCI DSS REQUIREMENTS
# =================================================================

requirement_1_compliant if { requirement_1.pci_requirement_1_compliant }  # Network Security Controls
requirement_2_compliant if { requirement_2.pci_requirement_2_compliant }  # Secure Configurations
requirement_3_compliant if { requirement_3.pci_requirement_3_compliant }  # Protect Stored CHD
requirement_4_compliant if { requirement_4.pci_requirement_4_compliant }  # Protect CHD in Transit
requirement_5_compliant if { requirement_5.pci_requirement_5_compliant }  # Malware Protection
requirement_6_compliant if { requirement_6.pci_requirement_6_compliant }  # Secure Development
requirement_7_compliant if { requirement_7.pci_requirement_7_compliant }  # Restrict Access
requirement_8_compliant if { requirement_8.pci_requirement_8_compliant }  # User Authentication
requirement_9_compliant if { requirement_9.pci_requirement_9_compliant }  # Physical Access
requirement_10_compliant if { requirement_10.pci_requirement_10_compliant } # Logging & Monitoring
requirement_11_compliant if { requirement_11.pci_requirement_11_compliant } # Security Testing
requirement_12_compliant if { requirement_12.pci_requirement_12_compliant } # Governance & Policy

# =================================================================
# PCI DSS LEVEL DETERMINATION
# =================================================================

pci_validation_level := level if {
	input.pci.transaction_volume.annual >= 6000000
	level := "Level 1"
} else := level if {
	input.pci.transaction_volume.annual >= 1000000
	level := "Level 2"
} else := level if {
	input.pci.transaction_volume.annual >= 20000
	level := "Level 3"
} else := level if {
	input.pci.transaction_volume.annual < 20000
	level := "Level 4"
} else := "Unknown"

# Cardholder Data Environment (CDE) scope validation
cde_scope_defined if {
	input.pci.cde.boundaries.documented == true
	input.pci.cde.systems.inventoried == true
	input.pci.cde.data_flows.mapped == true
	input.pci.cde.network_diagram.current == true
}

# =================================================================
# OVERALL COMPLIANCE
# =================================================================

all_requirements_compliant if {
	requirement_1_compliant
	requirement_2_compliant
	requirement_3_compliant
	requirement_4_compliant
	requirement_5_compliant
	requirement_6_compliant
	requirement_7_compliant
	requirement_8_compliant
	requirement_9_compliant
	requirement_10_compliant
	requirement_11_compliant
	requirement_12_compliant
}

pci_program_management if {
	input.pci.program.policies.established == true
	input.pci.program.roles.defined == true
	input.pci.program.training.conducted == true
	input.pci.program.documentation.maintained == true
	input.pci.program.risk_assessment.performed_annually == true
}

overall_pci_dss_compliant if {
	all_requirements_compliant
	cde_scope_defined
	pci_program_management
}

# Count of passing requirements (out of 12)
requirements_passing := count([r |
	some r in [
		requirement_1_compliant,
		requirement_2_compliant,
		requirement_3_compliant,
		requirement_4_compliant,
		requirement_5_compliant,
		requirement_6_compliant,
		requirement_7_compliant,
		requirement_8_compliant,
		requirement_9_compliant,
		requirement_10_compliant,
		requirement_11_compliant,
		requirement_12_compliant,
	]
	r == true
])

# =================================================================
# SCORING (weighted — data protection and access control weighted highest)
# =================================================================

requirement_scores := {
	"req_1_network_security":       requirement_1.pci_requirement_1_score,
	"req_2_system_hardening":       requirement_2.pci_requirement_2_score,
	"req_3_stored_data":            requirement_3.pci_requirement_3_score,
	"req_4_transmission_security":  requirement_4.pci_requirement_4_score,
	"req_5_malware_protection":     requirement_5.pci_requirement_5_score,
	"req_6_secure_development":     requirement_6.pci_requirement_6_score,
	"req_7_access_restriction":     requirement_7.pci_requirement_7_score,
	"req_8_authentication":         requirement_8.pci_requirement_8_score,
	"req_9_physical_access":        requirement_9.pci_requirement_9_score,
	"req_10_logging_monitoring":    requirement_10.pci_requirement_10_score,
	"req_11_security_testing":      requirement_11.pci_requirement_11_score,
	"req_12_governance":            requirement_12.pci_requirement_12_score,
}

pci_dss_compliance_score := score if {
	score := (
		(requirement_1.pci_requirement_1_score   * 0.08) +
		(requirement_2.pci_requirement_2_score   * 0.08) +
		(requirement_3.pci_requirement_3_score   * 0.12) +
		(requirement_4.pci_requirement_4_score   * 0.10) +
		(requirement_5.pci_requirement_5_score   * 0.07) +
		(requirement_6.pci_requirement_6_score   * 0.08) +
		(requirement_7.pci_requirement_7_score   * 0.10) +
		(requirement_8.pci_requirement_8_score   * 0.12) +
		(requirement_9.pci_requirement_9_score   * 0.05) +
		(requirement_10.pci_requirement_10_score * 0.08) +
		(requirement_11.pci_requirement_11_score * 0.07) +
		(requirement_12.pci_requirement_12_score * 0.05)
	)
}

# =================================================================
# DETAILED FINDINGS REPORT
# =================================================================

pci_dss_detailed_findings := {
	"standard": "PCI DSS v4.0",
	"validation_level": pci_validation_level,
	"requirements_passing": requirements_passing,
	"requirements_total": 12,
	"compliance_status": {
		"req_1_network_security":      requirement_1_compliant,
		"req_2_system_hardening":      requirement_2_compliant,
		"req_3_stored_data":           requirement_3_compliant,
		"req_4_transmission_security": requirement_4_compliant,
		"req_5_malware_protection":    requirement_5_compliant,
		"req_6_secure_development":    requirement_6_compliant,
		"req_7_access_restriction":    requirement_7_compliant,
		"req_8_authentication":        requirement_8_compliant,
		"req_9_physical_access":       requirement_9_compliant,
		"req_10_logging_monitoring":   requirement_10_compliant,
		"req_11_security_testing":     requirement_11_compliant,
		"req_12_governance":           requirement_12_compliant,
		"all_requirements_compliant":  all_requirements_compliant,
		"cde_scope_defined":           cde_scope_defined,
		"overall_pci_dss_compliant":   overall_pci_dss_compliant,
	},
	"scores": {
		"by_requirement": requirement_scores,
		"overall_weighted": pci_dss_compliance_score,
	},
	"requirement_details": {
		"requirement_1":  requirement_1.pci_requirement_1_findings,
		"requirement_2":  requirement_2.pci_requirement_2_findings,
		"requirement_3":  requirement_3.pci_requirement_3_findings,
		"requirement_4":  requirement_4.pci_requirement_4_findings,
		"requirement_5":  requirement_5.pci_requirement_5_findings,
		"requirement_6":  requirement_6.pci_requirement_6_findings,
		"requirement_7":  requirement_7.pci_requirement_7_findings,
		"requirement_8":  requirement_8.pci_requirement_8_findings,
		"requirement_9":  requirement_9.pci_requirement_9_findings,
		"requirement_10": requirement_10.pci_requirement_10_findings,
		"requirement_11": requirement_11.pci_requirement_11_findings,
		"requirement_12": requirement_12.pci_requirement_12_findings,
	},
}
