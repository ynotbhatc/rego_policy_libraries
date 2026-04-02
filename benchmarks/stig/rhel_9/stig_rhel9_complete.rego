package stig.rhel_9

# DISA STIG for RHEL 9 - Master Aggregator
# STIG Version: V2R2 | Released: October 2024
# Aggregates all modules: configuration_management, services, software_integrity,
#   file_permissions, audit_logging, ssh_config, account_auth, network, pki_crypto
#
# Endpoint: POST http://192.168.4.62:8181/v1/data/stig/rhel_9/stig_assessment

import rego.v1

import data.stig.rhel_9.configuration_management
import data.stig.rhel_9.services
import data.stig.rhel_9.software_integrity
import data.stig.rhel_9.file_permissions
import data.stig.rhel_9.audit_logging
import data.stig.rhel_9.ssh_config
import data.stig.rhel_9.account_auth
import data.stig.rhel_9.network
import data.stig.rhel_9.pki_crypto

# =============================================================================
# MODULE FINDING SETS
# =============================================================================

cm_findings := configuration_management.findings

svc_findings := services.findings

si_findings := software_integrity.findings

fp_findings := file_permissions.findings

al_findings := audit_logging.findings

ssh_findings := ssh_config.findings

aa_findings := account_auth.findings

net_findings := network.findings

pki_findings := pki_crypto.findings

# =============================================================================
# AGGREGATE ALL FINDINGS
# =============================================================================

# Build the complete findings list by successively concatenating module arrays
_findings_step1 := array.concat(cm_findings, svc_findings)

_findings_step2 := array.concat(_findings_step1, si_findings)

_findings_step3 := array.concat(_findings_step2, fp_findings)

_findings_step4 := array.concat(_findings_step3, al_findings)

_findings_step5 := array.concat(_findings_step4, ssh_findings)

_findings_step6 := array.concat(_findings_step5, aa_findings)

_findings_step7 := array.concat(_findings_step6, net_findings)

all_findings := array.concat(_findings_step7, pki_findings)

# =============================================================================
# SEVERITY COUNTS
# =============================================================================

cat_i_open_findings contains f if {
	some f in all_findings
	f.severity == "CAT I"
	f.status == "Open"
}

cat_ii_open_findings contains f if {
	some f in all_findings
	f.severity == "CAT II"
	f.status == "Open"
}

cat_iii_open_findings contains f if {
	some f in all_findings
	f.severity == "CAT III"
	f.status == "Open"
}

total_findings := count(all_findings)

open_findings_count := count([f | some f in all_findings; f.status == "Open"])

not_a_finding_count := count([f | some f in all_findings; f.status == "Not_a_Finding"])

not_applicable_count := count([f | some f in all_findings; f.status == "Not_Applicable"])

not_reviewed_count := count([f | some f in all_findings; f.status == "Not_Reviewed"])

# =============================================================================
# COMPLIANCE DETERMINATION
# =============================================================================

# Overall compliant: no CAT I findings open
default overall_compliant := false

overall_compliant if {
	count(cat_i_open_findings) == 0
}

# Fully compliant: no findings open at any severity
default fully_compliant := false

fully_compliant if {
	open_findings_count == 0
}

# =============================================================================
# MODULE COMPLIANCE STATUS
# =============================================================================

module_status := {
	"configuration_management": configuration_management.compliant,
	"services": services.compliant,
	"software_integrity": software_integrity.compliant,
	"file_permissions": file_permissions.compliant,
	"audit_logging": audit_logging.compliant,
	"ssh_config": ssh_config.compliant,
	"account_auth": account_auth.compliant,
	"network": network.compliant,
	"pki_crypto": pki_crypto.compliant,
}

# =============================================================================
# MASTER ASSESSMENT REPORT
# =============================================================================

stig_assessment := {
	"metadata": {
		"stig_title": "Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
		"version": "V2R2",
		"release_date": "2024-10-25",
		"platform": "RHEL 9",
		"assessed_host": input.system_info.hostname,
		"os_version": input.system_info.os_version,
	},
	"summary": {
		"total_findings": total_findings,
		"open": open_findings_count,
		"not_a_finding": not_a_finding_count,
		"not_applicable": not_applicable_count,
		"not_reviewed": not_reviewed_count,
		"cat_i_open": count(cat_i_open_findings),
		"cat_ii_open": count(cat_ii_open_findings),
		"cat_iii_open": count(cat_iii_open_findings),
		"overall_compliant": overall_compliant,
		"fully_compliant": fully_compliant,
	},
	"module_status": module_status,
	"findings": all_findings,
}
