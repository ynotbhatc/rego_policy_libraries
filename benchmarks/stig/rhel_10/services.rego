# METADATA
# title: "DISA STIG for RHEL 10 - Services Module"
# custom:
#   class: security
#   framework: stig_rhel_10
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 6
#     cited: 5
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_10.services

# DISA STIG for RHEL 10 - Services Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/services.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Unnecessary/insecure services that must be disabled

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule RHEL 10 does not carry)

# Helper: package not installed. Fail closed: only an explicit `false` counts.
pkg_absent(pkg) if input.packages[pkg] == false

# Helper: at least one alias is explicitly absent and no alias is installed.
pkgs_absent(names) if {
	some n in names
	pkg_absent(n)
	every m in names {
		not input.packages[m] == true
	}
}

# Helper: service is inactive or masked. Fail closed: a service with no
# reported state is NOT treated as disabled (absent telemetry is not evidence).
service_disabled(svc) if input.services[svc] in {"inactive", "masked"}

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-10-200090 | V-280951 | CAT I
# FTP server must not be running
default ftp_server_disabled := false

# title: the vsftpd package must not be installed (an inactive ftpd service is not enough)
ftp_server_disabled if pkg_absent("vsftpd")

status_rhel_10_200090 := "Not_a_Finding" if ftp_server_disabled

else := "Open"

finding_rhel_10_200090 := {
	"vuln_id": "V-280951",
	"stig_id": "RHEL-10-200090",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must not have a File Transfer Protocol (FTP) server package installed.",
	"status": status_rhel_10_200090,
	"fix_text": "Remove vsftpd: dnf remove vsftpd -y",
}

# RHEL-10-200020 | V-280944 | CAT I
# telnet server must not be installed
default telnet_server_absent := false

telnet_server_absent if pkgs_absent(["telnet-server", "telnetd"])

status_rhel_10_200020 := "Not_a_Finding" if telnet_server_absent

else := "Open"

finding_rhel_10_200020 := {
	"vuln_id": "V-280944",
	"stig_id": "RHEL-10-200020",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must not have the \"telnet-server\" package installed.",
	"status": status_rhel_10_200020,
	"fix_text": "Remove telnet-server: dnf remove telnet-server -y",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-200050 | V-280947 | CAT II
# TFTP server must not be installed
default tftp_server_absent := false

tftp_server_absent if pkg_absent("tftp-server")

status_rhel_10_200050 := "Not_a_Finding" if tftp_server_absent

else := "Open"

finding_rhel_10_200050 := {
	"vuln_id": "V-280947",
	"stig_id": "RHEL-10-200050",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not have a Trivial File Transfer Protocol (TFTP) server package installed unless it is required by the mission, and if required, the TFTP daemon must be configured to operate in secure mode.",
	"status": status_rhel_10_200050,
	"fix_text": "Remove tftp-server: dnf remove tftp-server -y",
}

# RHEL-10-701210 | V-281323 | CAT II
# autofs must be disabled
default autofs_disabled := false

autofs_disabled if service_disabled("autofs")

status_rhel_10_701210 := "Not_a_Finding" if autofs_disabled

else := "Open"

finding_rhel_10_701210 := {
	"vuln_id": "V-281323",
	"stig_id": "RHEL-10-701210",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must disable file system automount function unless required.",
	"status": status_rhel_10_701210,
	"fix_text": "Disable autofs: systemctl disable --now autofs",
}

# RHEL-10-200010 | V-280943 | CAT II
# NFS server must not be running unless required
default nfs_disabled := false

nfs_disabled if service_disabled("nfs-server")
nfs_disabled if service_disabled("nfsd")

status_rhel_10_200010 := "Not_a_Finding" if nfs_disabled

else := "Open"

finding_rhel_10_200010 := {
	"vuln_id": "V-280943",
	"stig_id": "RHEL-10-200010",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not have the \"nfs-utils\" package installed.",
	"status": status_rhel_10_200010,
	"fix_text": "Disable NFS server: systemctl disable --now nfs-server",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_10_200090,
	finding_rhel_10_200020,
]

cat_ii_findings := [
	finding_rhel_10_200050,
	finding_rhel_10_701210,
	finding_rhel_10_200010,
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

# `compliant`: no open finding at ANY category (CAT I, II or III), as in the RHEL 8/9 modules.
# `cat_i_compliant`: the CAT-I-only meaning, for gating on the critical subset.
open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

default cat_i_compliant := false

cat_i_compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "services",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
