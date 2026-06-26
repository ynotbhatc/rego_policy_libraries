package nist.csf.detect

import rego.v1

# NIST Cybersecurity Framework 2.0 — DETECT (DE) function
# Develop and implement appropriate activities to identify the occurrence
# of a cybersecurity event in a timely manner.

default compliant := false

# DE.AE — Anomalies and Events
violation contains msg if {
    not input.detect.anomalies_events.baseline_established
    msg := "CSF DE.AE-01: Baseline of network operations and expected data flows not established"
}

violation contains msg if {
    not input.detect.anomalies_events.detected_events_analyzed
    msg := "CSF DE.AE-02: Detected events not analyzed to understand attack targets/methods"
}

violation contains msg if {
    not input.detect.anomalies_events.event_data_aggregated
    msg := "CSF DE.AE-03: Event data not aggregated and correlated from multiple sources"
}

violation contains msg if {
    not input.detect.anomalies_events.impact_determined
    msg := "CSF DE.AE-04: Impact of events not determined"
}

violation contains msg if {
    not input.detect.anomalies_events.alert_thresholds_established
    msg := "CSF DE.AE-05: Incident alert thresholds not established"
}

# DE.CM — Security Continuous Monitoring
violation contains msg if {
    not input.detect.continuous_monitoring.network_monitored
    msg := "CSF DE.CM-01: Network not monitored to detect potential cybersecurity events"
}

violation contains msg if {
    not input.detect.continuous_monitoring.physical_environment_monitored
    msg := "CSF DE.CM-02: Physical environment not monitored for unauthorized access"
}

violation contains msg if {
    not input.detect.continuous_monitoring.personnel_activity_monitored
    msg := "CSF DE.CM-03: Personnel activity not monitored for anomalous behavior"
}

violation contains msg if {
    not input.detect.continuous_monitoring.malicious_code_detected
    msg := "CSF DE.CM-04: Malicious code not detected via continuous scanning"
}

violation contains msg if {
    not input.detect.continuous_monitoring.unauthorized_mobile_code_detected
    msg := "CSF DE.CM-05: Unauthorized mobile code not detected"
}

violation contains msg if {
    not input.detect.continuous_monitoring.external_provider_activity_monitored
    msg := "CSF DE.CM-06: External service provider activity not monitored"
}

violation contains msg if {
    not input.detect.continuous_monitoring.unauthorized_personnel_devices_monitored
    msg := "CSF DE.CM-07: Monitoring for unauthorized personnel/connections/devices/software not performed"
}

violation contains msg if {
    not input.detect.continuous_monitoring.vulnerability_scans_performed
    msg := "CSF DE.CM-08: Vulnerability scans not performed"
}

# DE.DP — Detection Processes
violation contains msg if {
    not input.detect.detection_processes.roles_defined
    msg := "CSF DE.DP-01: Roles and responsibilities for detection not well-defined"
}

violation contains msg if {
    not input.detect.detection_processes.activities_comply_with_requirements
    msg := "CSF DE.DP-02: Detection activities don't comply with all applicable requirements"
}

violation contains msg if {
    not input.detect.detection_processes.detection_processes_tested
    msg := "CSF DE.DP-03: Detection processes not tested"
}

violation contains msg if {
    not input.detect.detection_processes.event_information_communicated
    msg := "CSF DE.DP-04: Event detection information not communicated"
}

violation contains msg if {
    not input.detect.detection_processes.detection_processes_improved
    msg := "CSF DE.DP-05: Detection processes not continuously improved"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "function": "DETECT",
    "controls_evaluated": 18,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
