package stig.rhel_8.services

# DISA STIG for RHEL 8 - Services Module
# STIG Version: V1R13 | Released: July 2024

import rego.v1

default compliant := false

service_disabled(svc) if { input.services[svc] == "inactive" }
service_disabled(svc) if { input.services[svc] == "masked" }
service_disabled(svc) if { not input.services[svc] }

pkg_absent(pkg) if { input.packages[pkg] == false }
pkg_absent(pkg) if { not input.packages[pkg] }

# =============================================================================
# CAT I
# =============================================================================

# RHEL-08-040000 | V-230491 | CAT I - telnet-server must not be installed
default no_telnet_server := false
no_telnet_server if { pkg_absent("telnet-server") }

status_rhel_08_040000 := "Not_a_Finding" if { no_telnet_server } else := "Open"
finding_rhel_08_040000 := {
	"vuln_id": "V-230491",
	"stig_id": "RHEL-08-040000",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not have the telnet-server package installed",
	"status": status_rhel_08_040000,
	"fix_text": "dnf remove telnet-server -y",
}

# RHEL-08-040010 | V-230492 | CAT I - rsh-server must not be installed
default no_rsh_server := false
no_rsh_server if { pkg_absent("rsh-server") }

status_rhel_08_040010 := "Not_a_Finding" if { no_rsh_server } else := "Open"
finding_rhel_08_040010 := {
	"vuln_id": "V-230492",
	"stig_id": "RHEL-08-040010",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not have the rsh-server package installed",
	"status": status_rhel_08_040010,
	"fix_text": "dnf remove rsh-server -y",
}

# RHEL-08-040020 | V-230493 | CAT I - ypserv must not be installed
default no_ypserv := false
no_ypserv if { pkg_absent("ypserv") }

status_rhel_08_040020 := "Not_a_Finding" if { no_ypserv } else := "Open"
finding_rhel_08_040020 := {
	"vuln_id": "V-230493",
	"stig_id": "RHEL-08-040020",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not have the ypserv package installed",
	"status": status_rhel_08_040020,
	"fix_text": "dnf remove ypserv -y",
}

# RHEL-08-040030 | V-230494 | CAT I - tftp-server must not be installed
default no_tftp_server := false
no_tftp_server if { pkg_absent("tftp-server") }

status_rhel_08_040030 := "Not_a_Finding" if { no_tftp_server } else := "Open"
finding_rhel_08_040030 := {
	"vuln_id": "V-230494",
	"stig_id": "RHEL-08-040030",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not have the tftp-server package installed",
	"status": status_rhel_08_040030,
	"fix_text": "dnf remove tftp-server -y",
}

# =============================================================================
# CAT II
# =============================================================================

# RHEL-08-040040 | V-230495 | CAT II - autofs must be disabled
default autofs_disabled := false
autofs_disabled if { service_disabled("autofs") }

status_rhel_08_040040 := "Not_a_Finding" if { autofs_disabled } else := "Open"
finding_rhel_08_040040 := {
	"vuln_id": "V-230495",
	"stig_id": "RHEL-08-040040",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must disable the autofs service",
	"status": status_rhel_08_040040,
	"fix_text": "systemctl disable --now autofs",
}

# RHEL-08-040050 | V-230496 | CAT II - xinetd must not be installed
default no_xinetd := false
no_xinetd if { pkg_absent("xinetd") }

status_rhel_08_040050 := "Not_a_Finding" if { no_xinetd } else := "Open"
finding_rhel_08_040050 := {
	"vuln_id": "V-230496",
	"stig_id": "RHEL-08-040050",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not have the xinetd package installed",
	"status": status_rhel_08_040050,
	"fix_text": "dnf remove xinetd -y",
}

# RHEL-08-040060 | V-230497 | CAT II - Bluetooth must be disabled
default bluetooth_disabled := false
bluetooth_disabled if { service_disabled("bluetooth") }
bluetooth_disabled if { input.kernel_modules["bluetooth"].blacklisted == true }

status_rhel_08_040060 := "Not_a_Finding" if { bluetooth_disabled } else := "Open"
finding_rhel_08_040060 := {
	"vuln_id": "V-230497",
	"stig_id": "RHEL-08-040060",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must disable the Bluetooth service",
	"status": status_rhel_08_040060,
	"fix_text": "systemctl disable --now bluetooth",
}

# RHEL-08-040070 | V-230498 | CAT II - SNMP must not be running
default no_snmp := false
no_snmp if { service_disabled("snmpd") }
no_snmp if { pkg_absent("net-snmp") }

status_rhel_08_040070 := "Not_a_Finding" if { no_snmp } else := "Open"
finding_rhel_08_040070 := {
	"vuln_id": "V-230498",
	"stig_id": "RHEL-08-040070",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not have the net-snmp package installed unless required",
	"status": status_rhel_08_040070,
	"fix_text": "dnf remove net-snmp -y",
}

# RHEL-08-040080 | V-230499 | CAT II - NFS server must not be running
default no_nfs := false
no_nfs if { service_disabled("nfs-server") }

status_rhel_08_040080 := "Not_a_Finding" if { no_nfs } else := "Open"
finding_rhel_08_040080 := {
	"vuln_id": "V-230499",
	"stig_id": "RHEL-08-040080",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not have the nfs-utils package installed unless required",
	"status": status_rhel_08_040080,
	"fix_text": "systemctl disable --now nfs-server",
}

# RHEL-08-040090 | V-230500 | CAT II - Avahi daemon must be disabled
default no_avahi := false
no_avahi if { service_disabled("avahi-daemon") }

status_rhel_08_040090 := "Not_a_Finding" if { no_avahi } else := "Open"
finding_rhel_08_040090 := {
	"vuln_id": "V-230500",
	"stig_id": "RHEL-08-040090",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must disable the avahi-daemon service",
	"status": status_rhel_08_040090,
	"fix_text": "systemctl disable --now avahi-daemon",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_040000,
	finding_rhel_08_040010,
	finding_rhel_08_040020,
	finding_rhel_08_040030,
]

cat_ii_findings := [
	finding_rhel_08_040040,
	finding_rhel_08_040050,
	finding_rhel_08_040060,
	finding_rhel_08_040070,
	finding_rhel_08_040080,
	finding_rhel_08_040090,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if { count(open_cat_i) == 0 }

compliance_report := {
	"module": "services",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
