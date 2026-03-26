# PCI DSS v4.0 Requirement 2 - Apply Secure Configurations to All System Components
# Ensures vendor defaults are changed and unnecessary functions are removed

package pci_dss.system_hardening.requirement_2

import rego.v1

# =================================================================
# 2.1 - Processes and mechanisms for applying secure configurations
# =================================================================

system_hardening_policies_established if {
	input.pci.system_hardening.policies.documented == true
	input.pci.system_hardening.policies.approved == true
	input.pci.system_hardening.policies.current == true
	input.pci.system_hardening.policies.reviewed_annually == true
}

system_hardening_roles_defined if {
	input.pci.system_hardening.roles.defined == true
	input.pci.system_hardening.responsibilities.assigned == true
	input.pci.system_hardening.accountability.established == true
}

configuration_standards_maintained if {
	input.pci.system_hardening.configuration_standards.documented == true
	input.pci.system_hardening.configuration_standards.applied_to_all_systems == true
	input.pci.system_hardening.configuration_standards.reviewed_after_vendor_updates == true
}

# =================================================================
# 2.2 - System components are configured and managed securely
# =================================================================

# Default passwords changed on all system components
default_passwords_changed if {
	input.pci.hardening.default_credentials.changed == true
	input.pci.hardening.default_credentials.verified_on_new_systems == true
	input.pci.hardening.default_credentials.vendor_supplied_removed == true
}

# Unnecessary functionality removed from system components
unnecessary_functionality_removed if {
	input.pci.hardening.unnecessary_services.removed == true
	input.pci.hardening.unnecessary_protocols.disabled == true
	input.pci.hardening.unnecessary_ports.closed == true
	input.pci.hardening.unnecessary_functions.disabled == true
	input.pci.hardening.unnecessary_scripts.removed == true
}

# Single primary function per server (separation of roles)
single_primary_function_enforced if {
	input.pci.hardening.server_roles.single_primary_function == true
	input.pci.hardening.server_roles.documented == true
	input.pci.hardening.server_roles.justified == true
}

# System components protect against known vulnerabilities
known_vulnerabilities_mitigated if {
	input.pci.hardening.security_patches.current == true
	input.pci.hardening.security_patches.applied_within_one_month == true
	input.pci.hardening.vulnerability_management.implemented == true
}

# =================================================================
# 2.2.1 - Configuration standards for all system component types
# =================================================================

# Industry-accepted hardening standards used (CIS, NIST, DISA STIG)
hardening_standards_applied if {
	input.pci.hardening.standards.industry_accepted == true
	input.pci.hardening.standards.cis_benchmarks_referenced == true
	input.pci.hardening.standards.applied_to_all_component_types == true
	input.pci.hardening.standards.regularly_reviewed == true
}

# OS hardening
os_hardening_complete if {
	input.pci.hardening.os.unnecessary_services_disabled == true
	input.pci.hardening.os.host_based_firewall_enabled == true
	input.pci.hardening.os.unnecessary_users_removed == true
	input.pci.hardening.os.file_permissions_restricted == true
	input.pci.hardening.os.logging_enabled == true
}

# Database hardening
database_hardening_complete if {
	input.pci.hardening.database.default_accounts_disabled == true
	input.pci.hardening.database.unnecessary_procedures_removed == true
	input.pci.hardening.database.access_restricted == true
	input.pci.hardening.database.audit_logging_enabled == true
}

# Network device hardening
network_device_hardening_complete if {
	input.pci.hardening.network_devices.default_passwords_changed == true
	input.pci.hardening.network_devices.unnecessary_services_disabled == true
	input.pci.hardening.network_devices.management_access_restricted == true
	input.pci.hardening.network_devices.snmp_v3_configured == true
	input.pci.hardening.network_devices.firmware_current == true
}

# =================================================================
# 2.2.7 - All non-console administrative access is encrypted
# =================================================================

non_console_admin_access_encrypted if {
	input.pci.admin_access.non_console.encrypted == true
	input.pci.admin_access.non_console.strong_cryptography == true
	input.pci.admin_access.non_console.telnet_disabled == true
	input.pci.admin_access.non_console.ftp_disabled == true
	input.pci.admin_access.non_console.ssh_v2_only == true
	input.pci.admin_access.non_console.tls_enforced == true
}

# =================================================================
# 2.3 - Wireless environments are configured and managed securely
# =================================================================

wireless_security_configured if {
	# Only applies if wireless is in-scope for CDE
	not input.pci.wireless.in_scope_for_cde
} else if {
	input.pci.wireless.in_scope_for_cde
	input.pci.wireless.default_settings.changed == true
	input.pci.wireless.wpa3_or_wpa2.enabled == true
	input.pci.wireless.wep.disabled == true
	input.pci.wireless.ssid.default_changed == true
	input.pci.wireless.ssid.cde_ssid_not_broadcast == true
	input.pci.wireless.rogue_detection.implemented == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_2_compliant if {
	system_hardening_policies_established
	system_hardening_roles_defined
	configuration_standards_maintained
	default_passwords_changed
	unnecessary_functionality_removed
	known_vulnerabilities_mitigated
	hardening_standards_applied
	os_hardening_complete
	non_console_admin_access_encrypted
	wireless_security_configured
}

pci_requirement_2_score := score if {
	controls := [
		system_hardening_policies_established,
		system_hardening_roles_defined,
		configuration_standards_maintained,
		default_passwords_changed,
		unnecessary_functionality_removed,
		single_primary_function_enforced,
		known_vulnerabilities_mitigated,
		hardening_standards_applied,
		os_hardening_complete,
		database_hardening_complete,
		network_device_hardening_complete,
		non_console_admin_access_encrypted,
		wireless_security_configured,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_2_findings := {
	"requirement_2_1": {
		"policies_established": system_hardening_policies_established,
		"roles_defined": system_hardening_roles_defined,
		"standards_maintained": configuration_standards_maintained,
	},
	"requirement_2_2": {
		"default_passwords_changed": default_passwords_changed,
		"unnecessary_functionality_removed": unnecessary_functionality_removed,
		"single_primary_function": single_primary_function_enforced,
		"known_vulnerabilities_mitigated": known_vulnerabilities_mitigated,
	},
	"hardening_by_component": {
		"os": os_hardening_complete,
		"database": database_hardening_complete,
		"network_devices": network_device_hardening_complete,
		"hardening_standards_applied": hardening_standards_applied,
	},
	"requirement_2_2_7": {
		"non_console_admin_encrypted": non_console_admin_access_encrypted,
	},
	"requirement_2_3": {
		"wireless_security": wireless_security_configured,
	},
	"overall_score": pci_requirement_2_score,
	"overall_compliant": pci_requirement_2_compliant,
}
