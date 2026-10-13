# METADATA
# title: "DISA STIG for Oracle Linux 9 - Services Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_9
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 6
#     cited: 5
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: orchestrator
#     as_of: v2.4.0
package stig.oracle_linux_9.services

# DISA STIG for Oracle Linux 9 - Services Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/services.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Unnecessary/insecure services that must be disabled

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule Oracle Linux 9 does not carry)

# Helper: package not installed
pkg_absent(pkg) if {
	input.packages[pkg] == false
}

pkg_absent(pkg) if {
	not input.packages[pkg]
}

# Helper: check if service is inactive or not installed
service_disabled(svc) if {
	val := input.services[svc]
	val == "inactive"
}

service_disabled(svc) if {
	val := input.services[svc]
	val == "masked"
}

service_disabled(svc) if {
	not input.services[svc]
}

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL09-00-000135 | V-271463 | CAT I
# TFTP server must not be installed
default tftp_server_absent := false

tftp_server_absent if { pkg_absent("tftp-server") }

status_ol09_00_000135 := "Not_a_Finding" if { tftp_server_absent } else := "Open"

finding_ol09_00_000135 := {
	"vuln_id": "V-271463",
	"stig_id": "OL09-00-000135",
	"severity": "CAT I",
	"rule_title": "OL 9 must not have a Trivial File Transfer Protocol (TFTP) server package installed.",
	"status": status_ol09_00_000135,
	"fix_text": "Remove tftp-server: dnf remove tftp-server -y",
}

# OL09-00-000130 | V-271462 | CAT I
# FTP server must not be running
default ftp_server_disabled := false

ftp_server_disabled if {
	service_disabled("vsftpd")
	pkg_absent("vsftpd")
}

ftp_server_disabled if {
	service_disabled("ftpd")
}

status_ol09_00_000130 := "Not_a_Finding" if { ftp_server_disabled } else := "Open"

finding_ol09_00_000130 := {
	"vuln_id": "V-271462",
	"stig_id": "OL09-00-000130",
	"severity": "CAT I",
	"rule_title": "OL 9 must not have a File Transfer Protocol (FTP) server package installed.",
	"status": status_ol09_00_000130,
	"fix_text": "Remove vsftpd: dnf remove vsftpd -y",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-000110 | V-271458 | CAT II
# telnet server must not be installed
default telnet_server_absent := false

telnet_server_absent if { pkg_absent("telnet-server") }
telnet_server_absent if { pkg_absent("telnetd") }

status_ol09_00_000110 := "Not_a_Finding" if { telnet_server_absent } else := "Open"

finding_ol09_00_000110 := {
	"vuln_id": "V-271458",
	"stig_id": "OL09-00-000110",
	"severity": "CAT II",
	"rule_title": "OL 9 must not have the telnet-server package installed.",
	"status": status_ol09_00_000110,
	"fix_text": "Remove telnet-server: dnf remove telnet-server -y",
}

# OL09-00-000125 | V-271461 | CAT II
# xinetd must not be installed
default xinetd_absent := false

xinetd_absent if { pkg_absent("xinetd") }

status_ol09_00_000125 := "Not_a_Finding" if { xinetd_absent } else := "Open"

finding_ol09_00_000125 := {
	"vuln_id": "V-271461",
	"stig_id": "OL09-00-000125",
	"severity": "CAT II",
	"rule_title": "OL 9 must not have the tuned package installed.",
	"status": status_ol09_00_000125,
	"fix_text": "Remove xinetd: dnf remove xinetd -y",
}

# OL09-00-000100 | V-271456 | CAT II
# NFS server must not be running unless required
default nfs_disabled := false

nfs_disabled if { service_disabled("nfs-server") }
nfs_disabled if { service_disabled("nfsd") }

status_ol09_00_000100 := "Not_a_Finding" if { nfs_disabled } else := "Open"

finding_ol09_00_000100 := {
	"vuln_id": "V-271456",
	"stig_id": "OL09-00-000100",
	"severity": "CAT II",
	"rule_title": "OL 9 must not have the nfs-utils package installed.",
	"status": status_ol09_00_000100,
	"fix_text": "Disable NFS server: systemctl disable --now nfs-server",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol09_00_000135,
	finding_ol09_00_000130,
]

cat_ii_findings := [
	finding_ol09_00_000110,
	finding_ol09_00_000125,
	finding_ol09_00_000100,
]

cat_iii_findings := []

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "services",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
