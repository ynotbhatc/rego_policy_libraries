package cmmc.system_information_integrity

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.14: System and Information Integrity
# NIST SP 800-171 Rev 2 — 7 Practices
# =============================================================================

# 3.14.1 — Identify, report, and correct information and information system
#           flaws in a timely manner. (L1)
default compliant_3_14_1 := false
compliant_3_14_1 if {
    input.integrity.flaw_remediation_policy == true
    input.integrity.patch_management_program == true
    input.integrity.critical_patch_days <= 30
}

violation_3_14_1 contains msg if {
    not input.integrity.flaw_remediation_policy
    msg := "3.14.1: No policy for identifying and correcting system flaws in a timely manner"
}
violation_3_14_1 contains msg if {
    not input.integrity.patch_management_program
    msg := "3.14.1: No patch management program to identify and remediate system vulnerabilities"
}
violation_3_14_1 contains msg if {
    input.integrity.critical_patch_days > 30
    msg := sprintf("3.14.1: Critical patches applied within %v days (must be ≤30)", [input.integrity.critical_patch_days])
}

# 3.14.2 — Provide protection from malicious code at appropriate locations
#           within organizational systems. (L1)
default compliant_3_14_2 := false
compliant_3_14_2 if {
    input.integrity.antimalware_installed == true
    input.integrity.antimalware_realtime_enabled == true
    input.integrity.antimalware_covers_entry_exit_points == true
}

violation_3_14_2 contains msg if {
    not input.integrity.antimalware_installed
    msg := "3.14.2: Anti-malware protection is not installed on CUI systems"
}
violation_3_14_2 contains msg if {
    not input.integrity.antimalware_realtime_enabled
    msg := "3.14.2: Real-time anti-malware scanning is not enabled"
}
violation_3_14_2 contains msg if {
    not input.integrity.antimalware_covers_entry_exit_points
    msg := "3.14.2: Anti-malware protection does not cover all entry and exit points (email, web, removable media)"
}

# 3.14.3 — Monitor system security alerts and advisories and take action in
#           response. (L1)
default compliant_3_14_3 := false
compliant_3_14_3 if {
    input.integrity.security_alerts_monitored == true
    input.integrity.threat_intel_feeds_subscribed == true
    input.integrity.alerts_actioned == true
}

violation_3_14_3 contains msg if {
    not input.integrity.security_alerts_monitored
    msg := "3.14.3: System security alerts and advisories are not monitored"
}
violation_3_14_3 contains msg if {
    not input.integrity.threat_intel_feeds_subscribed
    msg := "3.14.3: Not subscribed to threat intelligence or security advisory feeds (CISA, US-CERT, etc.)"
}
violation_3_14_3 contains msg if {
    not input.integrity.alerts_actioned
    msg := "3.14.3: Security alerts and advisories are received but not acted upon"
}

# 3.14.4 — Update malicious code protection mechanisms when new releases are
#           available. (L1)
default compliant_3_14_4 := false
compliant_3_14_4 if {
    input.integrity.antimalware_auto_update == true
    input.integrity.signature_update_frequency_hours <= 24
}

violation_3_14_4 contains msg if {
    not input.integrity.antimalware_auto_update
    msg := "3.14.4: Anti-malware signatures are not automatically updated when new releases are available"
}
violation_3_14_4 contains msg if {
    input.integrity.signature_update_frequency_hours > 24
    msg := sprintf("3.14.4: Anti-malware signatures updated every %v hours (must be ≤24)", [input.integrity.signature_update_frequency_hours])
}

# 3.14.5 — Perform periodic scans of organizational systems and real-time scans
#           of files from external sources as files are downloaded, opened, or
#           executed. (L1)
default compliant_3_14_5 := false
compliant_3_14_5 if {
    input.integrity.periodic_system_scans == true
    input.integrity.scan_frequency_days <= 7
    input.integrity.realtime_file_scanning == true
    input.integrity.download_scanning_enabled == true
}

violation_3_14_5 contains msg if {
    not input.integrity.periodic_system_scans
    msg := "3.14.5: Periodic anti-malware scans of CUI systems are not performed"
}
violation_3_14_5 contains msg if {
    input.integrity.scan_frequency_days > 7
    msg := sprintf("3.14.5: System scans run every %v days (must be at least weekly)", [input.integrity.scan_frequency_days])
}
violation_3_14_5 contains msg if {
    not input.integrity.realtime_file_scanning
    msg := "3.14.5: Real-time scanning of files is not performed when files are opened or executed"
}
violation_3_14_5 contains msg if {
    not input.integrity.download_scanning_enabled
    msg := "3.14.5: Files downloaded from external sources are not scanned before use"
}

# 3.14.6 — Monitor organizational systems, including inbound and outbound
#           communications traffic, to detect attacks and indicators of
#           potential attacks. (L2)
default compliant_3_14_6 := false
compliant_3_14_6 if {
    input.integrity.ids_ips_deployed == true
    input.integrity.inbound_traffic_monitored == true
    input.integrity.outbound_traffic_monitored == true
    input.integrity.attack_indicators_detected == true
}

violation_3_14_6 contains msg if {
    not input.integrity.ids_ips_deployed
    msg := "3.14.6: Intrusion detection/prevention system (IDS/IPS) is not deployed for CUI systems"
}
violation_3_14_6 contains msg if {
    not input.integrity.inbound_traffic_monitored
    msg := "3.14.6: Inbound network traffic to CUI systems is not monitored for attacks"
}
violation_3_14_6 contains msg if {
    not input.integrity.outbound_traffic_monitored
    msg := "3.14.6: Outbound network traffic from CUI systems is not monitored for exfiltration indicators"
}
violation_3_14_6 contains msg if {
    not input.integrity.attack_indicators_detected
    msg := "3.14.6: System monitoring does not detect indicators of attack or compromise"
}

# 3.14.7 — Identify unauthorized use of organizational systems. (L2)
default compliant_3_14_7 := false
compliant_3_14_7 if {
    input.integrity.unauthorized_use_detection == true
    input.integrity.baseline_behavior_established == true
    input.integrity.anomaly_detection_enabled == true
    input.integrity.unauthorized_access_alerted == true
}

violation_3_14_7 contains msg if {
    not input.integrity.unauthorized_use_detection
    msg := "3.14.7: Unauthorized use of CUI systems is not identified or detected"
}
violation_3_14_7 contains msg if {
    not input.integrity.baseline_behavior_established
    msg := "3.14.7: No baseline of normal system behavior established for anomaly comparison"
}
violation_3_14_7 contains msg if {
    not input.integrity.anomaly_detection_enabled
    msg := "3.14.7: Anomaly detection is not enabled to identify unusual system activity"
}
violation_3_14_7 contains msg if {
    not input.integrity.unauthorized_access_alerted
    msg := "3.14.7: Alerts are not generated when unauthorized system use is detected"
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations_1_4 := array.concat(
    array.concat(
        [v | some v in violation_3_14_1],
        [v | some v in violation_3_14_2]
    ),
    array.concat(
        [v | some v in violation_3_14_3],
        [v | some v in violation_3_14_4]
    )
)

all_violations_5_7 := array.concat(
    [v | some v in violation_3_14_5],
    array.concat(
        [v | some v in violation_3_14_6],
        [v | some v in violation_3_14_7]
    )
)

all_violations := array.concat(all_violations_1_4, all_violations_5_7)

practices := [
    {"id": "3.14.1", "level": 1, "compliant": compliant_3_14_1},
    {"id": "3.14.2", "level": 1, "compliant": compliant_3_14_2},
    {"id": "3.14.3", "level": 1, "compliant": compliant_3_14_3},
    {"id": "3.14.4", "level": 1, "compliant": compliant_3_14_4},
    {"id": "3.14.5", "level": 1, "compliant": compliant_3_14_5},
    {"id": "3.14.6", "level": 2, "compliant": compliant_3_14_6},
    {"id": "3.14.7", "level": 2, "compliant": compliant_3_14_7},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "System and Information Integrity",
    "domain_id": "3.14",
    "total_practices": 7,
    "passing": passing_count,
    "failing": 7 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
