package stig.rhel_8

# DISA STIG for RHEL 8 - Master Aggregator
# STIG Version: V1R13 | Released: July 2024
# Endpoint: POST http://192.168.4.62:8181/v1/data/stig/rhel_8/stig_assessment

import rego.v1

import data.stig.rhel_8.configuration_management
import data.stig.rhel_8.services
import data.stig.rhel_8.ssh_config
import data.stig.rhel_8.account_auth
import data.stig.rhel_8.audit_logging
import data.stig.rhel_8.network
import data.stig.rhel_8.file_permissions

# =============================================================================
# AGGREGATE ALL FINDINGS
# =============================================================================

_step1 := array.concat(configuration_management.findings, services.findings)
_step2 := array.concat(_step1, ssh_config.findings)
_step3 := array.concat(_step2, account_auth.findings)
_step4 := array.concat(_step3, audit_logging.findings)
_step5 := array.concat(_step4, network.findings)
all_findings := array.concat(_step5, file_permissions.findings)

# =============================================================================
# COUNTS
# =============================================================================

cat_i_open contains f if {
	some f in all_findings
	f.severity == "CAT I"
	f.status == "Open"
}

cat_ii_open contains f if {
	some f in all_findings
	f.severity == "CAT II"
	f.status == "Open"
}

open_count := count([f | some f in all_findings; f.status == "Open"])

not_a_finding_count := count([f | some f in all_findings; f.status == "Not_a_Finding"])

# =============================================================================
# COMPLIANCE
# =============================================================================

default overall_compliant := false

overall_compliant if { count(cat_i_open) == 0 }

default fully_compliant := false

fully_compliant if { open_count == 0 }

# =============================================================================
# MASTER ASSESSMENT REPORT
# =============================================================================

stig_assessment := {
	"metadata": {
		"stig_title": "Red Hat Enterprise Linux 8 Security Technical Implementation Guide",
		"version": "V1R13",
		"release_date": "2024-07-24",
		"platform": "RHEL 8",
		"assessed_host": input.system_info.hostname,
		"os_version": input.system_info.os_version,
	},
	"summary": {
		"total_findings": count(all_findings),
		"open": open_count,
		"not_a_finding": not_a_finding_count,
		"cat_i_open": count(cat_i_open),
		"cat_ii_open": count(cat_ii_open),
		"overall_compliant": overall_compliant,
		"fully_compliant": fully_compliant,
	},
	"module_status": {
		"configuration_management": configuration_management.compliant,
		"services": services.compliant,
		"ssh_config": ssh_config.compliant,
		"account_auth": account_auth.compliant,
		"audit_logging": audit_logging.compliant,
		"network": network.compliant,
		"file_permissions": file_permissions.compliant,
	},
	"findings": all_findings,
}
