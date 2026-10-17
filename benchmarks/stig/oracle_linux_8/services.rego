# METADATA
# title: "DISA STIG for Oracle Linux 8 - Services Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 4
#     cited: 3
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.oracle_linux_8.services

# DISA STIG for Oracle Linux 8 - Services Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/services.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Unnecessary/insecure services that must be disabled

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule Oracle Linux 8 does not carry)

# Evidence: an inventory must have been collected. A missing/empty inventory is not
# proof that a package is absent.
packages_collected if {
	is_object(input.packages)
	count(input.packages) > 0
}

services_collected if {
	is_object(input.services)
	count(input.services) > 0
}

# Helper: package not installed (only provable against a collected inventory)
pkg_absent(pkg) if {
	packages_collected
	input.packages[pkg] == false
}

pkg_absent(pkg) if {
	packages_collected
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
	services_collected
	not input.services[svc]
}

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL08-00-040190 | V-248873 | CAT I
# TFTP server must not be installed
default tftp_server_absent := false

tftp_server_absent if { pkg_absent("tftp-server") }

status_ol08_00_040190 := "Not_a_Finding" if { tftp_server_absent } else := "Open"

finding_ol08_00_040190 := {
	"vuln_id": "V-248873",
	"stig_id": "OL08-00-040190",
	"severity": "CAT I",
	"rule_title": "The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for OL 8 operational support.",
	"status": status_ol08_00_040190,
	"fix_text": "Remove tftp-server: dnf remove tftp-server -y",
}

# OL08-00-040000 | V-248823 | CAT I
# telnet server must not be installed
default telnet_server_absent := false

# Both package names must be absent (either one installed is a finding).
telnet_server_absent if {
	pkg_absent("telnet-server")
	pkg_absent("telnetd")
}

status_ol08_00_040000 := "Not_a_Finding" if { telnet_server_absent } else := "Open"

finding_ol08_00_040000 := {
	"vuln_id": "V-248823",
	"stig_id": "OL08-00-040000",
	"severity": "CAT I",
	"rule_title": "OL 8 must not have the telnet-server package installed.",
	"status": status_ol08_00_040000,
	"fix_text": "Remove telnet-server: dnf remove telnet-server -y",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-040002 | V-248825 | CAT II
# NFS server must not be running unless required
default nfs_disabled := false

nfs_disabled if { service_disabled("nfs-server") }
nfs_disabled if { service_disabled("nfsd") }

status_ol08_00_040002 := "Not_a_Finding" if { nfs_disabled } else := "Open"

finding_ol08_00_040002 := {
	"vuln_id": "V-248825",
	"stig_id": "OL08-00-040002",
	"severity": "CAT II",
	"rule_title": "OL 8 must not have the sendmail package installed.",
	"status": status_ol08_00_040002,
	"fix_text": "Disable NFS server: systemctl disable --now nfs-server",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol08_00_040190,
	finding_ol08_00_040000,
]

cat_ii_findings := [
	finding_ol08_00_040002,
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
