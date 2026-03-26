package cis_windows_server_2022.system_services

# CIS Windows Server 2022 Benchmark v3.0.0 - Section 5: System Services

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	[v | some v in disabled_service_violations],
	[v | some v in running_service_violations],
)

# Services that should be disabled on non-DC member servers

# CIS 5.1: Bluetooth Audio Gateway Service = Disabled
disabled_service_violations contains msg if {
	input.services["BTAGService"].start_type != "Disabled"
	msg := sprintf("CIS 5.1: Bluetooth Audio Gateway Service (BTAGService) should be Disabled (current: %s)", [input.services["BTAGService"].start_type])
}

# CIS 5.2: Bluetooth Support Service = Disabled
disabled_service_violations contains msg if {
	input.services["bthserv"].start_type != "Disabled"
	msg := sprintf("CIS 5.2: Bluetooth Support Service (bthserv) should be Disabled (current: %s)", [input.services["bthserv"].start_type])
}

# CIS 5.3: Computer Browser = Disabled
disabled_service_violations contains msg if {
	input.services["Browser"].start_type != "Disabled"
	not input.services["Browser"].not_installed
	msg := sprintf("CIS 5.3: Computer Browser service (Browser) should be Disabled (current: %s)", [input.services["Browser"].start_type])
}

# CIS 5.4: Downloaded Maps Manager = Disabled
disabled_service_violations contains msg if {
	input.services["MapsBroker"].start_type != "Disabled"
	msg := sprintf("CIS 5.4: Downloaded Maps Manager (MapsBroker) should be Disabled (current: %s)", [input.services["MapsBroker"].start_type])
}

# CIS 5.5: Geolocation Service = Disabled
disabled_service_violations contains msg if {
	input.services["lfsvc"].start_type != "Disabled"
	msg := sprintf("CIS 5.5: Geolocation Service (lfsvc) should be Disabled (current: %s)", [input.services["lfsvc"].start_type])
}

# CIS 5.6: IIS Admin Service = Disabled (unless IIS is required)
disabled_service_violations contains msg if {
	not input.services["IISADMIN"].not_installed
	input.services["IISADMIN"].start_type != "Disabled"
	not input.require_iis
	msg := sprintf("CIS 5.6: IIS Admin Service should be Disabled (current: %s)", [input.services["IISADMIN"].start_type])
}

# CIS 5.7: Infrared Monitor Service = Disabled
disabled_service_violations contains msg if {
	not input.services["irmon"].not_installed
	input.services["irmon"].start_type != "Disabled"
	msg := sprintf("CIS 5.7: Infrared Monitor Service (irmon) should be Disabled (current: %s)", [input.services["irmon"].start_type])
}

# CIS 5.8: Internet Connection Sharing = Disabled
disabled_service_violations contains msg if {
	input.services["SharedAccess"].start_type != "Disabled"
	msg := sprintf("CIS 5.8: Internet Connection Sharing (SharedAccess) should be Disabled (current: %s)", [input.services["SharedAccess"].start_type])
}

# CIS 5.9: Link-Layer Topology Discovery Mapper = Disabled
disabled_service_violations contains msg if {
	input.services["lltdsvc"].start_type != "Disabled"
	msg := sprintf("CIS 5.9: Link-Layer Topology Discovery Mapper (lltdsvc) should be Disabled (current: %s)", [input.services["lltdsvc"].start_type])
}

# CIS 5.10: LxssManager (WSL) = Disabled
disabled_service_violations contains msg if {
	not input.services["LxssManager"].not_installed
	input.services["LxssManager"].start_type != "Disabled"
	msg := sprintf("CIS 5.10: Windows Subsystem for Linux (LxssManager) should be Disabled (current: %s)", [input.services["LxssManager"].start_type])
}

# CIS 5.11: Microsoft FTP Service = Disabled
disabled_service_violations contains msg if {
	not input.services["FTPSVC"].not_installed
	input.services["FTPSVC"].start_type != "Disabled"
	not input.require_ftp
	msg := sprintf("CIS 5.11: Microsoft FTP Service (FTPSVC) should be Disabled (current: %s)", [input.services["FTPSVC"].start_type])
}

# CIS 5.12: Microsoft iSCSI Initiator Service = Disabled (unless required)
disabled_service_violations contains msg if {
	input.services["MSiSCSI"].start_type != "Disabled"
	not input.require_iscsi
	msg := sprintf("CIS 5.12: Microsoft iSCSI Initiator (MSiSCSI) should be Disabled (current: %s)", [input.services["MSiSCSI"].start_type])
}

# CIS 5.13: OpenSSH SSH Server = Disabled (unless required)
disabled_service_violations contains msg if {
	not input.services["sshd"].not_installed
	input.services["sshd"].start_type != "Disabled"
	not input.require_ssh_server
	msg := sprintf("CIS 5.13: OpenSSH SSH Server (sshd) should be Disabled unless required (current: %s)", [input.services["sshd"].start_type])
}

# CIS 5.14: Peer Name Resolution Protocol = Disabled
disabled_service_violations contains msg if {
	input.services["PNRPsvc"].start_type != "Disabled"
	msg := sprintf("CIS 5.14: Peer Name Resolution Protocol (PNRPsvc) should be Disabled (current: %s)", [input.services["PNRPsvc"].start_type])
}

# CIS 5.15: Peer Networking Grouping = Disabled
disabled_service_violations contains msg if {
	input.services["p2psvc"].start_type != "Disabled"
	msg := sprintf("CIS 5.15: Peer Networking Grouping (p2psvc) should be Disabled (current: %s)", [input.services["p2psvc"].start_type])
}

# CIS 5.16: Remote Desktop Configuration = Disabled (unless RDS)
disabled_service_violations contains msg if {
	input.services["SessionEnv"].start_type == "Automatic"
	not input.require_rds
	msg := "CIS 5.16: Remote Desktop Configuration (SessionEnv) should not be Automatic unless RDS is required"
}

# CIS 5.17: Remote Procedure Call Locator = Disabled
disabled_service_violations contains msg if {
	input.services["RpcLocator"].start_type != "Disabled"
	not input.services["RpcLocator"].not_installed
	msg := sprintf("CIS 5.17: Remote Procedure Call Locator (RpcLocator) should be Disabled (current: %s)", [input.services["RpcLocator"].start_type])
}

# CIS 5.18: Remote Registry = Disabled
disabled_service_violations contains msg if {
	input.services["RemoteRegistry"].start_type != "Disabled"
	msg := sprintf("CIS 5.18: Remote Registry service should be Disabled (current: %s)", [input.services["RemoteRegistry"].start_type])
}

# Services that must NOT be running
# CIS 5.19: Routing and Remote Access = Disabled
running_service_violations contains msg if {
	input.services["RemoteAccess"].state == "Running"
	msg := "CIS 5.19: Routing and Remote Access service is Running (should be Disabled)"
}

# CIS 5.20: Server (for SMB) - check SMBv1
running_service_violations contains msg if {
	input.services.smb1_enabled
	msg := "CIS 5.20: SMBv1 server is enabled (should be disabled)"
}

# CIS 5.21: Simple TCP/IP Services = Disabled
disabled_service_violations contains msg if {
	not input.services["simptcp"].not_installed
	input.services["simptcp"].start_type != "Disabled"
	msg := sprintf("CIS 5.21: Simple TCP/IP Services (simptcp) should be Disabled (current: %s)", [input.services["simptcp"].start_type])
}

# CIS 5.22: SNMP Service = Disabled (unless required)
disabled_service_violations contains msg if {
	not input.services["SNMP"].not_installed
	input.services["SNMP"].start_type != "Disabled"
	not input.require_snmp
	msg := sprintf("CIS 5.22: SNMP Service should be Disabled unless required (current: %s)", [input.services["SNMP"].start_type])
}

# CIS 5.23: Telnet = Disabled
disabled_service_violations contains msg if {
	not input.services["TlntSvr"].not_installed
	input.services["TlntSvr"].start_type != "Disabled"
	msg := sprintf("CIS 5.23: Telnet service (TlntSvr) should be Disabled (current: %s)", [input.services["TlntSvr"].start_type])
}

# CIS 5.24: TFTP Daemon = Disabled
disabled_service_violations contains msg if {
	not input.services["tftpd"].not_installed
	input.services["tftpd"].start_type != "Disabled"
	msg := sprintf("CIS 5.24: TFTP Daemon should be Disabled (current: %s)", [input.services["tftpd"].start_type])
}

# CIS 5.25: World Wide Web Publishing Service (W3SVC) = Disabled (unless IIS required)
disabled_service_violations contains msg if {
	not input.services["W3SVC"].not_installed
	input.services["W3SVC"].start_type != "Disabled"
	not input.require_iis
	msg := sprintf("CIS 5.25: World Wide Web Publishing Service (W3SVC) should be Disabled unless IIS required (current: %s)", [input.services["W3SVC"].start_type])
}

# CIS 5.26: Xbox services = Disabled
disabled_service_violations contains msg if {
	not input.services["XblAuthManager"].not_installed
	input.services["XblAuthManager"].start_type != "Disabled"
	msg := "CIS 5.26: Xbox Live Auth Manager (XblAuthManager) should be Disabled"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"disabled_service_violations": count(disabled_service_violations),
	"running_service_violations": count(running_service_violations),
	"controls_checked": 26,
	"section": "5 System Services",
	"benchmark": "CIS Windows Server 2022 v3.0.0",
}
