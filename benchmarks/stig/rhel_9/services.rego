# METADATA
# title: "DISA STIG for RHEL 9 - Services Module"
# custom:
#   class: security
#   framework: stig_rhel_9
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
package stig.rhel_9.services

# DISA STIG for RHEL 9 - Services Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: Unnecessary/insecure services that must be disabled

import rego.v1

default compliant := false

# Helper: service is inactive or masked. Fail closed: a service with no
# reported state is NOT treated as disabled (absent telemetry is not evidence).
service_disabled(svc) if input.services[svc] in {"inactive", "masked"}

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

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-215060 | V-257835 | CAT I
# TFTP server must not be installed
default tftp_server_absent := false

tftp_server_absent if pkg_absent("tftp-server")

status_rhel_09_215060 := "Not_a_Finding" if tftp_server_absent

else := "Open"

finding_rhel_09_215060 := {
	"vuln_id": "V-257835",
	"stig_id": "RHEL-09-215060",
	"severity": "CAT I",
	"rule_title": "The Trivial File Transfer Protocol (TFTP) server must not be installed unless it is required, and if required, the RHEL 9 TFTP daemon must be configured to operate in secure mode.",
	"status": status_rhel_09_215060,
	"fix_text": "Remove tftp-server: dnf remove tftp-server -y",
}

# RHEL-09-215015 | V-257826 | CAT I
# FTP server must not be running
default ftp_server_disabled := false

# title: the vsftpd package must not be installed (an inactive ftpd service is not enough)
ftp_server_disabled if pkg_absent("vsftpd")

status_rhel_09_215015 := "Not_a_Finding" if ftp_server_disabled

else := "Open"

finding_rhel_09_215015 := {
	"vuln_id": "V-257826",
	"stig_id": "RHEL-09-215015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not have a File Transfer Protocol (FTP) server package installed.",
	"status": status_rhel_09_215015,
	"fix_text": "Remove vsftpd: dnf remove vsftpd -y",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-215040 | V-257831 | CAT II
# telnet server must not be installed
default telnet_server_absent := false

telnet_server_absent if pkgs_absent(["telnet-server", "telnetd"])

status_rhel_09_215040 := "Not_a_Finding" if telnet_server_absent

else := "Open"

finding_rhel_09_215040 := {
	"vuln_id": "V-257831",
	"stig_id": "RHEL-09-215040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the telnet-server package installed.",
	"status": status_rhel_09_215040,
	"fix_text": "Remove telnet-server: dnf remove telnet-server -y",
}

# RHEL-09-231040 | V-257849 | CAT II
# autofs must be disabled
default autofs_disabled := false

autofs_disabled if service_disabled("autofs")

status_rhel_09_231040 := "Not_a_Finding" if autofs_disabled

else := "Open"

finding_rhel_09_231040 := {
	"vuln_id": "V-257849",
	"stig_id": "RHEL-09-231040",
	"severity": "CAT II",
	"rule_title": "The RHEL 9 file system automounter must be disabled.",
	"status": status_rhel_09_231040,
	"fix_text": "Disable autofs: systemctl disable --now autofs",
}

# RHEL-09-215025 | V-257828 | CAT II
# NFS server must not be running unless required
default nfs_disabled := false

nfs_disabled if service_disabled("nfs-server")
nfs_disabled if service_disabled("nfsd")

status_rhel_09_215025 := "Not_a_Finding" if nfs_disabled

else := "Open"

finding_rhel_09_215025 := {
	"vuln_id": "V-257828",
	"stig_id": "RHEL-09-215025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the nfs-utils package installed.",
	"status": status_rhel_09_215025,
	"fix_text": "Disable NFS server: systemctl disable --now nfs-server",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_215060,
	finding_rhel_09_215015,
]

cat_ii_findings := [
	finding_rhel_09_215040,
	finding_rhel_09_231040,
	finding_rhel_09_215025,
]

# No CAT III rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_iii_findings := array.concat([], [])

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

# `compliant`: no open finding at ANY category (CAT I, II or III).
# `cat_i_compliant`: the former CAT-I-only meaning, for gating on the critical subset.
default cat_i_compliant := false

open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

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
