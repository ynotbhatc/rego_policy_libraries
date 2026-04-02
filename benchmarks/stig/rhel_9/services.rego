package stig.rhel_9.services

# DISA STIG for RHEL 9 - Services Module
# STIG Version: V2R2 | Released: October 2024
# Covers: Unnecessary/insecure services that must be disabled

import rego.v1

default compliant := false

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

# Helper: package not installed
pkg_absent(pkg) if {
	input.packages[pkg] == false
}

pkg_absent(pkg) if {
	not input.packages[pkg]
}

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-291010 | V-257931 | CAT I
# telnet server must not be installed
default telnet_server_absent := false

telnet_server_absent if { pkg_absent("telnet-server") }
telnet_server_absent if { pkg_absent("telnetd") }

status_rhel_09_291010 := "Not_a_Finding" if { telnet_server_absent } else := "Open"

finding_rhel_09_291010 := {
	"vuln_id": "V-257931",
	"stig_id": "RHEL-09-291010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not have the telnet-server package installed",
	"status": status_rhel_09_291010,
	"fix_text": "Remove telnet-server: dnf remove telnet-server -y",
}

# RHEL-09-291015 | V-257932 | CAT I
# rsh-server must not be installed
default rsh_server_absent := false

rsh_server_absent if { pkg_absent("rsh-server") }
rsh_server_absent if { pkg_absent("rshd") }

status_rhel_09_291015 := "Not_a_Finding" if { rsh_server_absent } else := "Open"

finding_rhel_09_291015 := {
	"vuln_id": "V-257932",
	"stig_id": "RHEL-09-291015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not have the rsh-server package installed",
	"status": status_rhel_09_291015,
	"fix_text": "Remove rsh-server: dnf remove rsh-server -y",
}

# RHEL-09-291020 | V-257933 | CAT I
# ypserv (NIS server) must not be installed
default ypserv_absent := false

ypserv_absent if { pkg_absent("ypserv") }

status_rhel_09_291020 := "Not_a_Finding" if { ypserv_absent } else := "Open"

finding_rhel_09_291020 := {
	"vuln_id": "V-257933",
	"stig_id": "RHEL-09-291020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not have the ypserv package installed",
	"status": status_rhel_09_291020,
	"fix_text": "Remove ypserv: dnf remove ypserv -y",
}

# RHEL-09-291025 | V-257934 | CAT I
# TFTP server must not be installed
default tftp_server_absent := false

tftp_server_absent if { pkg_absent("tftp-server") }

status_rhel_09_291025 := "Not_a_Finding" if { tftp_server_absent } else := "Open"

finding_rhel_09_291025 := {
	"vuln_id": "V-257934",
	"stig_id": "RHEL-09-291025",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not have the tftp-server package installed",
	"status": status_rhel_09_291025,
	"fix_text": "Remove tftp-server: dnf remove tftp-server -y",
}

# RHEL-09-291030 | V-257935 | CAT I
# FTP server must not be running
default ftp_server_disabled := false

ftp_server_disabled if {
	service_disabled("vsftpd")
	pkg_absent("vsftpd")
}

ftp_server_disabled if {
	service_disabled("ftpd")
}

status_rhel_09_291030 := "Not_a_Finding" if { ftp_server_disabled } else := "Open"

finding_rhel_09_291030 := {
	"vuln_id": "V-257935",
	"stig_id": "RHEL-09-291030",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not have the vsftpd package installed unless mission requires FTP",
	"status": status_rhel_09_291030,
	"fix_text": "Remove vsftpd: dnf remove vsftpd -y",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-291035 | V-257936 | CAT II
# autofs must be disabled
default autofs_disabled := false

autofs_disabled if { service_disabled("autofs") }

status_rhel_09_291035 := "Not_a_Finding" if { autofs_disabled } else := "Open"

finding_rhel_09_291035 := {
	"vuln_id": "V-257936",
	"stig_id": "RHEL-09-291035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable the autofs service unless mission requires automounting",
	"status": status_rhel_09_291035,
	"fix_text": "Disable autofs: systemctl disable --now autofs",
}

# RHEL-09-291040 | V-257937 | CAT II
# xinetd must not be installed
default xinetd_absent := false

xinetd_absent if { pkg_absent("xinetd") }

status_rhel_09_291040 := "Not_a_Finding" if { xinetd_absent } else := "Open"

finding_rhel_09_291040 := {
	"vuln_id": "V-257937",
	"stig_id": "RHEL-09-291040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the xinetd package installed",
	"status": status_rhel_09_291040,
	"fix_text": "Remove xinetd: dnf remove xinetd -y",
}

# RHEL-09-291045 | V-257938 | CAT II
# Bluetooth must be disabled
default bluetooth_disabled := false

bluetooth_disabled if { service_disabled("bluetooth") }
bluetooth_disabled if { input.kernel_modules["bluetooth"].blacklisted == true }

status_rhel_09_291045 := "Not_a_Finding" if { bluetooth_disabled } else := "Open"

finding_rhel_09_291045 := {
	"vuln_id": "V-257938",
	"stig_id": "RHEL-09-291045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable the Bluetooth service",
	"status": status_rhel_09_291045,
	"fix_text": "Disable Bluetooth: systemctl disable --now bluetooth",
}

# RHEL-09-291050 | V-257939 | CAT II
# Avahi daemon must be disabled
default avahi_disabled := false

avahi_disabled if { service_disabled("avahi-daemon") }

status_rhel_09_291050 := "Not_a_Finding" if { avahi_disabled } else := "Open"

finding_rhel_09_291050 := {
	"vuln_id": "V-257939",
	"stig_id": "RHEL-09-291050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable the Avahi daemon service unless mission requires",
	"status": status_rhel_09_291050,
	"fix_text": "Disable avahi-daemon: systemctl disable --now avahi-daemon",
}

# RHEL-09-291055 | V-257940 | CAT II
# SNMP server must not be running
default snmp_disabled := false

snmp_disabled if { service_disabled("snmpd") }
snmp_disabled if { pkg_absent("net-snmp") }

status_rhel_09_291055 := "Not_a_Finding" if { snmp_disabled } else := "Open"

finding_rhel_09_291055 := {
	"vuln_id": "V-257940",
	"stig_id": "RHEL-09-291055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the net-snmp package installed unless required for operational support",
	"status": status_rhel_09_291055,
	"fix_text": "Remove net-snmp: dnf remove net-snmp -y",
}

# RHEL-09-291060 | V-257941 | CAT II
# NFS server must not be running unless required
default nfs_disabled := false

nfs_disabled if { service_disabled("nfs-server") }
nfs_disabled if { service_disabled("nfsd") }

status_rhel_09_291060 := "Not_a_Finding" if { nfs_disabled } else := "Open"

finding_rhel_09_291060 := {
	"vuln_id": "V-257941",
	"stig_id": "RHEL-09-291060",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the nfs-utils package installed unless mission requires",
	"status": status_rhel_09_291060,
	"fix_text": "Disable NFS server: systemctl disable --now nfs-server",
}

# RHEL-09-291065 | V-257942 | CAT II
# Print server (CUPS) must be disabled
default cups_disabled := false

cups_disabled if { service_disabled("cups") }

status_rhel_09_291065 := "Not_a_Finding" if { cups_disabled } else := "Open"

finding_rhel_09_291065 := {
	"vuln_id": "V-257942",
	"stig_id": "RHEL-09-291065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the cups package installed unless mission requires",
	"status": status_rhel_09_291065,
	"fix_text": "Remove cups: dnf remove cups -y",
}

# RHEL-09-291070 | V-257943 | CAT II
# DNS server must not be running unless required
default dns_disabled := false

dns_disabled if { service_disabled("named") }
dns_disabled if { pkg_absent("bind") }

status_rhel_09_291070 := "Not_a_Finding" if { dns_disabled } else := "Open"

finding_rhel_09_291070 := {
	"vuln_id": "V-257943",
	"stig_id": "RHEL-09-291070",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the bind package installed unless mission requires",
	"status": status_rhel_09_291070,
	"fix_text": "Remove bind: dnf remove bind -y",
}

# RHEL-09-291075 | V-257944 | CAT II
# DHCP server must not be running unless required
default dhcp_disabled := false

dhcp_disabled if { service_disabled("dhcpd") }
dhcp_disabled if { pkg_absent("dhcp-server") }

status_rhel_09_291075 := "Not_a_Finding" if { dhcp_disabled } else := "Open"

finding_rhel_09_291075 := {
	"vuln_id": "V-257944",
	"stig_id": "RHEL-09-291075",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the dhcp-server package installed unless mission requires",
	"status": status_rhel_09_291075,
	"fix_text": "Remove dhcp-server: dnf remove dhcp-server -y",
}

# RHEL-09-291080 | V-257945 | CAT II
# HTTP server (Apache) must not be running unless required
default httpd_disabled := false

httpd_disabled if { service_disabled("httpd") }
httpd_disabled if { pkg_absent("httpd") }

status_rhel_09_291080 := "Not_a_Finding" if { httpd_disabled } else := "Open"

finding_rhel_09_291080 := {
	"vuln_id": "V-257945",
	"stig_id": "RHEL-09-291080",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the httpd package installed unless mission requires",
	"status": status_rhel_09_291080,
	"fix_text": "Remove httpd: dnf remove httpd -y",
}

# RHEL-09-291085 | V-257946 | CAT II
# Samba server must not be running unless required
default smb_disabled := false

smb_disabled if { service_disabled("smb") }
smb_disabled if { pkg_absent("samba") }

status_rhel_09_291085 := "Not_a_Finding" if { smb_disabled } else := "Open"

finding_rhel_09_291085 := {
	"vuln_id": "V-257946",
	"stig_id": "RHEL-09-291085",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the samba package installed unless mission requires",
	"status": status_rhel_09_291085,
	"fix_text": "Remove samba: dnf remove samba -y",
}

# RHEL-09-291090 | V-257947 | CAT II
# Squid proxy server must not be running unless required
default squid_disabled := false

squid_disabled if { service_disabled("squid") }
squid_disabled if { pkg_absent("squid") }

status_rhel_09_291090 := "Not_a_Finding" if { squid_disabled } else := "Open"

finding_rhel_09_291090 := {
	"vuln_id": "V-257947",
	"stig_id": "RHEL-09-291090",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the squid package installed unless mission requires",
	"status": status_rhel_09_291090,
	"fix_text": "Remove squid: dnf remove squid -y",
}

# RHEL-09-291095 | V-257948 | CAT II
# rsync daemon must not be running
default rsync_disabled := false

rsync_disabled if { service_disabled("rsyncd") }
rsync_disabled if { pkg_absent("rsync-daemon") }

status_rhel_09_291095 := "Not_a_Finding" if { rsync_disabled } else := "Open"

finding_rhel_09_291095 := {
	"vuln_id": "V-257948",
	"stig_id": "RHEL-09-291095",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have the rsync-daemon package installed unless mission requires",
	"status": status_rhel_09_291095,
	"fix_text": "Remove rsync-daemon: dnf remove rsync-daemon -y",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_291010,
	finding_rhel_09_291015,
	finding_rhel_09_291020,
	finding_rhel_09_291025,
	finding_rhel_09_291030,
]

cat_ii_findings := [
	finding_rhel_09_291035,
	finding_rhel_09_291040,
	finding_rhel_09_291045,
	finding_rhel_09_291050,
	finding_rhel_09_291055,
	finding_rhel_09_291060,
	finding_rhel_09_291065,
	finding_rhel_09_291070,
	finding_rhel_09_291075,
	finding_rhel_09_291080,
	finding_rhel_09_291085,
	finding_rhel_09_291090,
	finding_rhel_09_291095,
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
