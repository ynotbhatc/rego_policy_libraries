# METADATA
# title: "DISA STIG for Oracle Linux 8 - Master Aggregator"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 9
#     cited: 2
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.0
package stig.oracle_linux_8

# DISA STIG for Oracle Linux 8 - Master Aggregator
# STIG Version: V2R10 | Released: 30 Sep 2026
# Aggregates all modules: configuration_management, services, software_integrity,
#   file_permissions, audit_logging, ssh_config, account_auth, network, pki_crypto
#
# Endpoints: POST http://localhost:8181/v1/data/stig/oracle_linux_8/stig_assessment
#            POST http://localhost:8181/v1/data/stig/oracle_linux_8/main/compliance_report  (fail-closed alias)

# Implemented: 93 of 450 Oracle Linux 8 V1R7 rules — those whose DISA title matches a rule the
# RHEL 9 modules implement. The remaining 357 are tracked follow-up, not silent absence.

# Implemented: 68 of 378 Oracle Linux 8 V2R10 rules — those whose DISA title matches a rule the
# Oracle Linux 9 modules implement. The remaining 310 are tracked follow-up, not silent absence.

import rego.v1

import data.stig.oracle_linux_8.configuration_management
import data.stig.oracle_linux_8.services
import data.stig.oracle_linux_8.software_integrity
import data.stig.oracle_linux_8.file_permissions
import data.stig.oracle_linux_8.audit_logging
import data.stig.oracle_linux_8.ssh_config
import data.stig.oracle_linux_8.account_auth
import data.stig.oracle_linux_8.network
import data.stig.oracle_linux_8.pki_crypto

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
		"stig_title": "Oracle Linux 8 Security Technical Implementation Guide",
		"version": "V2R10",
		"release_date": "2026-08-24",
		"platform": "Oracle Linux 8",
		"assessed_host": object.get(input, ["system_info", "hostname"], "unknown"),
		"os_version": object.get(input, ["system_info", "os_version"], "unknown"),
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

# =============================================================================
# UNIFORM LIBRARY ENTRYPOINT CONTRACT
# =============================================================================
# Consumed by the stig.oracle_linux_8.main alias's fail-closed gate (see
# stig_oracle_linux_8_main.rego): total_controls + open_findings are required.
# total_controls is derived from the module finding arrays, never hard-coded.

open_findings := [f | some f in all_findings; f.status == "Open"]

compliance_report := {
	"total_controls": count(all_findings),
	"open_findings": open_findings,
	"passed_controls": count(all_findings) - count(open_findings),
	"failed_controls": count(open_findings),
	"compliant": fully_compliant,
}
