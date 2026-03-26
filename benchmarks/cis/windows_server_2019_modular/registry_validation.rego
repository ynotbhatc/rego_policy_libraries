package cis_windows_server_2019.registry

# CIS Windows Server 2019 Benchmark v3.0.0 - Section 18: Administrative Templates (Registry)

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in network_violations], [v | some v in rdp_violations]),
	array.concat([v | some v in credential_violations], [v | some v in system_violations]),
)

# =============================================================================
# CIS 18.3: MS Security Guide (registry settings)
# =============================================================================

# CIS 18.3.1: Apply UAC restrictions to local accounts on network logon = Enabled
system_violations contains msg if {
	not input.registry.local_account_token_filter_policy_disabled
	msg := "CIS 18.3.1: UAC restrictions for local accounts on network logon should be enabled (LocalAccountTokenFilterPolicy = 0)"
}

# CIS 18.3.3: Configure SMB v1 client = Disabled
network_violations contains msg if {
	input.registry.smb1_client_enabled
	msg := "CIS 18.3.3: SMBv1 client driver should be disabled"
}

# CIS 18.3.4: Configure SMB v1 server = Disabled
network_violations contains msg if {
	input.registry.smb1_server_enabled
	msg := "CIS 18.3.4: SMBv1 server should be disabled"
}

# CIS 18.3.5: Enable Structured Exception Handling Overwrite Protection (SEHOP) = Enabled
system_violations contains msg if {
	not input.registry.sehop_enabled
	msg := "CIS 18.3.5: Structured Exception Handling Overwrite Protection (SEHOP) is not enabled"
}

# CIS 18.3.7: WDigest Authentication = Disabled
credential_violations contains msg if {
	input.registry.wdigest_enabled
	msg := "CIS 18.3.7: WDigest Authentication is enabled (should be disabled to prevent plaintext credential storage)"
}

# =============================================================================
# CIS 18.4: MSS (Legacy) Settings
# =============================================================================

# CIS 18.4.1: AutoAdminLogon = Disabled
credential_violations contains msg if {
	input.registry.auto_admin_logon_enabled
	msg := "CIS 18.4.1: AutoAdminLogon is enabled (should be disabled)"
}

# CIS 18.4.3: Disable IPv6 source routing
network_violations contains msg if {
	input.registry.ipv6_source_routing_protection < 2
	msg := sprintf("CIS 18.4.3: IPv6 source routing protection is %d, should be 2 (highest protection)", [input.registry.ipv6_source_routing_protection])
}

# CIS 18.4.4: Disable IPv4 source routing = Maximum Protection
network_violations contains msg if {
	input.registry.ip_source_routing_protection < 2
	msg := sprintf("CIS 18.4.4: IPv4 source routing protection is %d, should be 2 (highest protection)", [input.registry.ip_source_routing_protection])
}

# CIS 18.4.5: Enable ICMP redirect = Disabled
network_violations contains msg if {
	input.registry.icmp_redirect_enabled
	msg := "CIS 18.4.5: ICMP redirect is enabled (should be disabled)"
}

# CIS 18.4.8: Warning level for security event log = 90%
system_violations contains msg if {
	input.registry.security_log_warning_level < 90
	msg := sprintf("CIS 18.4.8: Security log warning level is %d%%, should be 90%% or higher", [input.registry.security_log_warning_level])
}

# CIS 18.4.11: Disable NetBIOS name release without authentication = Enabled
network_violations contains msg if {
	not input.registry.no_name_release_on_demand
	msg := "CIS 18.4.11: NetBIOS name release without authentication should be disabled"
}

# =============================================================================
# CIS 18.6: Network
# =============================================================================

# CIS 18.6.4.1: Configure NetBIOS settings = Disabled on non-DC
network_violations contains msg if {
	input.registry.netbios_node_type == 1
	msg := "CIS 18.6.4.1: NetBIOS node type is B-node (broadcast) - should be P-node or H-node"
}

# CIS 18.6.8.1: Enable insecure guest logons = Disabled
network_violations contains msg if {
	input.registry.insecure_guest_logons_enabled
	msg := "CIS 18.6.8.1: Insecure guest logons to SMB servers are enabled (should be disabled)"
}

# CIS 18.6.9.1: Turn off Microsoft Peer-to-Peer Networking Services = Enabled
network_violations contains msg if {
	not input.registry.p2p_networking_disabled
	msg := "CIS 18.6.9.1: Microsoft Peer-to-Peer Networking Services should be disabled"
}

# CIS 18.6.19.2.1: Turn off multicast name resolution = Enabled
network_violations contains msg if {
	not input.registry.llmnr_disabled
	msg := "CIS 18.6.19.2.1: Link-Local Multicast Name Resolution (LLMNR) should be disabled"
}

# =============================================================================
# CIS 18.8: Remote Desktop
# =============================================================================

# CIS 18.8.36.1: RDP connection encryption = Enabled (High)
rdp_violations contains msg if {
	input.registry.rdp_encryption_level < 3
	msg := sprintf("CIS 18.8.36.1: RDP encryption level is %d, should be 3 (High)", [input.registry.rdp_encryption_level])
}

# CIS 18.8.36.2: Set NLA for RDP = Enabled
rdp_violations contains msg if {
	not input.registry.rdp_nla_required
	msg := "CIS 18.8.36.2: Network Level Authentication (NLA) for RDP is not required"
}

# CIS 18.9.17: Credentials delegation = Disabled
credential_violations contains msg if {
	input.registry.allow_default_credentials_enabled
	msg := "CIS 18.9.17: Allow Default Credentials delegation is enabled (should be disabled)"
}

# =============================================================================
# CIS 18.10: Windows Components
# =============================================================================

# CIS 18.10.12.1: AutoRun disabled for all drives
system_violations contains msg if {
	input.registry.autorun_enabled
	msg := "CIS 18.10.12.1: AutoRun should be disabled for all drives"
}

# CIS 18.10.12.2: Autoplay disabled
system_violations contains msg if {
	not input.registry.autoplay_disabled
	msg := "CIS 18.10.12.2: AutoPlay should be disabled"
}

# CIS 18.10.15.1: Windows Error Reporting = Disabled
system_violations contains msg if {
	not input.registry.error_reporting_disabled
	msg := "CIS 18.10.15.1: Windows Error Reporting should be disabled"
}

# CIS 18.10.57.1: Prevent installation of devices that match device IDs = Enabled
system_violations contains msg if {
	not input.registry.device_install_restriction_enabled
	msg := "CIS 18.10.57.1: Device installation restrictions should be enabled"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"network_violations": count(network_violations),
	"rdp_violations": count(rdp_violations),
	"credential_violations": count(credential_violations),
	"system_violations": count(system_violations),
	"controls_checked": 22,
	"section": "18 Administrative Templates (Registry)",
	"benchmark": "CIS Windows Server 2019 v3.0.0",
}
