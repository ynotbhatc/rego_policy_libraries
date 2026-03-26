# PCI DSS v4.0 Requirement 11 - Test Security of Systems and Networks Regularly

package pci_dss.security_testing.requirement_11

import rego.v1

# =================================================================
# 11.1 - Processes and mechanisms for testing security
# =================================================================

security_testing_policies_established if {
	input.pci.security_testing.policies.documented == true
	input.pci.security_testing.policies.approved == true
	input.pci.security_testing.policies.current == true
	input.pci.security_testing.policies.reviewed_annually == true
}

security_testing_roles_defined if {
	input.pci.security_testing.roles.defined == true
	input.pci.security_testing.responsibilities.assigned == true
}

# =================================================================
# 11.2 - Wireless access points managed and tested
# =================================================================

wireless_access_point_testing if {
	input.pci.wireless.authorized_access_points.inventoried == true
	input.pci.wireless.rogue_detection.implemented == true
	input.pci.wireless.rogue_detection.frequency_days <= 90
	input.pci.wireless.unauthorized_access_points.alerts.configured == true
	input.pci.wireless.unauthorized_access_points.response.documented == true
}

# =================================================================
# 11.3 - External and internal vulnerabilities regularly identified, prioritized and addressed
# =================================================================

# Internal vulnerability scanning
internal_vulnerability_scanning if {
	input.pci.vuln_scanning.internal.performed == true
	input.pci.vuln_scanning.internal.frequency_days <= 90
	input.pci.vuln_scanning.internal.qualified_personnel == true
	input.pci.vuln_scanning.internal.after_significant_changes == true
	input.pci.vuln_scanning.internal.high_and_critical.remediated == true
	input.pci.vuln_scanning.internal.rescans.performed == true
}

# External vulnerability scanning by ASV
external_vulnerability_scanning if {
	input.pci.vuln_scanning.external.performed == true
	input.pci.vuln_scanning.external.frequency_days <= 90
	input.pci.vuln_scanning.external.asv.approved == true
	input.pci.vuln_scanning.external.passing_scan.achieved == true
	input.pci.vuln_scanning.external.after_significant_changes == true
}

# Vulnerability scan remediation
vulnerability_remediation if {
	input.pci.vuln_remediation.critical.within_30_days == true
	input.pci.vuln_remediation.high.within_30_days == true
	input.pci.vuln_remediation.medium.risk_based_timeline == true
	input.pci.vuln_remediation.tracking.implemented == true
	input.pci.vuln_remediation.verification.rescan_after_fix == true
}

# =================================================================
# 11.4 - External and internal penetration testing regularly performed
# =================================================================

penetration_testing if {
	input.pci.pen_testing.performed == true
	input.pci.pen_testing.frequency_months <= 12
	input.pci.pen_testing.after_significant_infrastructure_changes == true
	input.pci.pen_testing.qualified.independent_tester == true
	input.pci.pen_testing.scope.network_layer == true
	input.pci.pen_testing.scope.application_layer == true
	input.pci.pen_testing.scope.includes_cde_perimeter == true
	input.pci.pen_testing.scope.includes_critical_systems == true
}

# Penetration test remediation
pen_test_remediation if {
	input.pci.pen_testing.exploitable_vulnerabilities.corrected == true
	input.pci.pen_testing.retesting.performed_after_fixes == true
	input.pci.pen_testing.results.retained == true
}

# Segmentation testing
segmentation_testing if {
	input.pci.segmentation_testing.performed == true
	input.pci.segmentation_testing.frequency_months <= 6
	input.pci.segmentation_testing.penetration_testing_method == true
	input.pci.segmentation_testing.confirms_isolation == true
	input.pci.segmentation_testing.after_segmentation_changes == true
}

# =================================================================
# 11.5 - Network intrusion and unexpected file changes detected
# =================================================================

# Intrusion detection and prevention
ids_ips_deployed if {
	input.pci.ids_ips.deployed == true
	input.pci.ids_ips.coverage.all_cde_network_traffic == true
	input.pci.ids_ips.signatures.current == true
	input.pci.ids_ips.alerts.configured == true
	input.pci.ids_ips.monitoring.real_time == true
	input.pci.ids_ips.personnel.responds_to_alerts == true
}

# File integrity monitoring (FIM)
file_integrity_monitoring if {
	input.pci.fim.deployed == true
	input.pci.fim.critical_files.covered == true
	input.pci.fim.os_files.covered == true
	input.pci.fim.application_files.covered == true
	input.pci.fim.configuration_files.covered == true
	input.pci.fim.alerts.immediate == true
	input.pci.fim.comparison.against_baseline == true
	input.pci.fim.frequency_days <= 7
}

# =================================================================
# 11.6 - Unauthorized changes to payment pages detected and responded to
# =================================================================

payment_page_integrity if {
	# Only required if e-commerce with hosted payment pages
	not input.pci.ecommerce.payment_pages.in_scope
} else if {
	input.pci.ecommerce.payment_pages.in_scope
	input.pci.ecommerce.payment_pages.integrity_monitoring == true
	input.pci.ecommerce.payment_pages.change_detection.implemented == true
	input.pci.ecommerce.payment_pages.change_detection.frequency_days <= 7
	input.pci.ecommerce.payment_pages.script_inventory.maintained == true
	input.pci.ecommerce.payment_pages.content_security_policy.implemented == true
	input.pci.ecommerce.payment_pages.alerts.configured == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_11_compliant if {
	security_testing_policies_established
	security_testing_roles_defined
	wireless_access_point_testing
	internal_vulnerability_scanning
	external_vulnerability_scanning
	vulnerability_remediation
	penetration_testing
	pen_test_remediation
	segmentation_testing
	ids_ips_deployed
	file_integrity_monitoring
	payment_page_integrity
}

pci_requirement_11_score := score if {
	controls := [
		security_testing_policies_established,
		security_testing_roles_defined,
		wireless_access_point_testing,
		internal_vulnerability_scanning,
		external_vulnerability_scanning,
		vulnerability_remediation,
		penetration_testing,
		pen_test_remediation,
		segmentation_testing,
		ids_ips_deployed,
		file_integrity_monitoring,
		payment_page_integrity,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_11_findings := {
	"requirement_11_1": {
		"policies_established": security_testing_policies_established,
		"roles_defined": security_testing_roles_defined,
	},
	"requirement_11_2": {
		"wireless_ap_testing": wireless_access_point_testing,
	},
	"requirement_11_3": {
		"internal_scanning": internal_vulnerability_scanning,
		"external_scanning_asv": external_vulnerability_scanning,
		"vulnerability_remediation": vulnerability_remediation,
	},
	"requirement_11_4": {
		"penetration_testing": penetration_testing,
		"pen_test_remediation": pen_test_remediation,
		"segmentation_testing": segmentation_testing,
	},
	"requirement_11_5": {
		"ids_ips": ids_ips_deployed,
		"file_integrity_monitoring": file_integrity_monitoring,
	},
	"requirement_11_6": {
		"payment_page_integrity": payment_page_integrity,
	},
	"overall_score": pci_requirement_11_score,
	"overall_compliant": pci_requirement_11_compliant,
}
