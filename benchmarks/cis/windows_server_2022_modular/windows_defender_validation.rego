package cis_windows_server_2022.windows_defender

# CIS Windows Server 2022 Benchmark v3.0.0 - Section 18.10.42: Windows Defender Antivirus

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in av_violations], [v | some v in exploit_guard_violations]),
	[v | some v in network_protection_violations],
)

# =============================================================================
# CIS 18.10.42: Windows Defender Antivirus
# =============================================================================

# CIS 18.10.42.1: Turn off Windows Defender Antivirus = Disabled (i.e., Defender is ON)
av_violations contains msg if {
	not input.windows_defender.antivirus_enabled
	msg := "CIS 18.10.42.1: Windows Defender Antivirus is not enabled"
}

# CIS 18.10.42.5.1: Turn off real-time protection = Disabled (protection is ON)
av_violations contains msg if {
	not input.windows_defender.realtime_protection_enabled
	msg := "CIS 18.10.42.5.1: Windows Defender real-time protection is not enabled"
}

# CIS 18.10.42.5.2: Turn on behavior monitoring = Enabled
av_violations contains msg if {
	not input.windows_defender.behavior_monitoring_enabled
	msg := "CIS 18.10.42.5.2: Windows Defender behavior monitoring is not enabled"
}

# CIS 18.10.42.5.3: Scan all downloaded files and attachments = Enabled
av_violations contains msg if {
	not input.windows_defender.scan_downloads_enabled
	msg := "CIS 18.10.42.5.3: Windows Defender scanning of downloaded files and attachments is not enabled"
}

# CIS 18.10.42.5.4: Monitor file and program activity = Enabled
av_violations contains msg if {
	not input.windows_defender.file_activity_monitoring_enabled
	msg := "CIS 18.10.42.5.4: Windows Defender file and program activity monitoring is not enabled"
}

# CIS 18.10.42.6: Signature updates interval
av_violations contains msg if {
	input.windows_defender.signature_update_interval > 8
	msg := sprintf("CIS 18.10.42.6: Windows Defender signature update interval is %d hours, should be 8 or less", [input.windows_defender.signature_update_interval])
}

av_violations contains msg if {
	input.windows_defender.signature_age_days > 7
	msg := sprintf("CIS 18.10.42.6: Windows Defender signatures are %d days old, should be less than 7 days", [input.windows_defender.signature_age_days])
}

# CIS 18.10.42.7: Configure cloud-based protection = Enabled
av_violations contains msg if {
	not input.windows_defender.cloud_protection_enabled
	msg := "CIS 18.10.42.7: Windows Defender cloud-based protection (MAPS) is not enabled"
}

# CIS 18.10.42.7.1: Block at First Sight = Enabled
av_violations contains msg if {
	not input.windows_defender.block_at_first_sight_enabled
	msg := "CIS 18.10.42.7.1: Windows Defender 'Block at First Sight' is not enabled"
}

# =============================================================================
# CIS 18.10.42.3: Exploit Guard
# =============================================================================

# CIS 18.10.42.3.1: Attack Surface Reduction rules
exploit_guard_violations contains msg if {
	not input.windows_defender.asr_enabled
	msg := "CIS 18.10.42.3.1: Attack Surface Reduction (ASR) rules are not enabled"
}

exploit_guard_violations contains msg if {
	input.windows_defender.asr_enabled
	count(input.windows_defender.asr_rules) < 3
	msg := sprintf("CIS 18.10.42.3.1: Only %d ASR rules are configured, expected at least 3", [count(input.windows_defender.asr_rules)])
}

# CIS 18.10.42.3.2: Controlled Folder Access = Enabled
exploit_guard_violations contains msg if {
	not input.windows_defender.controlled_folder_access_enabled
	msg := "CIS 18.10.42.3.2: Controlled Folder Access is not enabled"
}

# CIS 18.10.42.3.3: Network Protection = Enabled (Block mode)
network_protection_violations contains msg if {
	input.windows_defender.network_protection_mode != "Block"
	input.windows_defender.network_protection_mode != "AuditMode"
	msg := sprintf("CIS 18.10.42.3.3: Network Protection mode is '%s', should be Block or AuditMode", [input.windows_defender.network_protection_mode])
}

# CIS 18.10.42.3.3: Prefer Block mode over Audit
network_protection_violations contains msg if {
	input.windows_defender.network_protection_mode == "AuditMode"
	msg := "CIS 18.10.42.3.3: Network Protection is in AuditMode - consider enabling Block mode for full protection"
}

# =============================================================================
# Windows Defender Firewall
# =============================================================================

# CIS 9.1.1: Windows Firewall Domain Profile = Enabled
av_violations contains msg if {
	not input.windows_defender.firewall_domain_enabled
	msg := "CIS 9.1.1: Windows Firewall Domain Profile is not enabled"
}

# CIS 9.2.1: Windows Firewall Private Profile = Enabled
av_violations contains msg if {
	not input.windows_defender.firewall_private_enabled
	msg := "CIS 9.2.1: Windows Firewall Private Profile is not enabled"
}

# CIS 9.3.1: Windows Firewall Public Profile = Enabled
av_violations contains msg if {
	not input.windows_defender.firewall_public_enabled
	msg := "CIS 9.3.1: Windows Firewall Public Profile is not enabled"
}

# CIS 9.1.2/9.2.2/9.3.2: Inbound connections blocked by default
av_violations contains msg if {
	input.windows_defender.firewall_domain_inbound_default != "Block"
	msg := sprintf("CIS 9.1.2: Firewall Domain inbound default is '%s', should be Block", [input.windows_defender.firewall_domain_inbound_default])
}

av_violations contains msg if {
	input.windows_defender.firewall_public_inbound_default != "Block"
	msg := sprintf("CIS 9.3.2: Firewall Public inbound default is '%s', should be Block", [input.windows_defender.firewall_public_inbound_default])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"av_violations": count(av_violations),
	"exploit_guard_violations": count(exploit_guard_violations),
	"network_protection_violations": count(network_protection_violations),
	"defender_status": {
		"antivirus_enabled": input.windows_defender.antivirus_enabled,
		"realtime_protection": input.windows_defender.realtime_protection_enabled,
		"cloud_protection": input.windows_defender.cloud_protection_enabled,
		"signature_age_days": input.windows_defender.signature_age_days,
	},
	"controls_checked": 18,
	"section": "18.10.42 Windows Defender / 9 Windows Firewall",
	"benchmark": "CIS Windows Server 2022 v3.0.0",
}
