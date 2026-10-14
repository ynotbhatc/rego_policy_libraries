# METADATA
# title: "NIST Cybersecurity Framework 2.0 — DETECT (DE) function"
# custom:
#   class: compliance
#   framework: nist_cybersecurity_framework_2_0
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 6
#     cited: 6
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.csf.detect

import rego.v1

# NIST Cybersecurity Framework 2.0 — DETECT (DE) function module.
# Develop and implement appropriate activities to identify the occurrence
# of a cybersecurity event in a timely manner.
#
# Fact checks. Each violation below is labelled with the CSF 2.0 subcategory it decides in nist.csf.main
# (CPRT ids, CSF_2_0_0). The checks were written against CSF 1.1; a check keeps deciding a subcategory only when
# its id is current in CSF 2.0 and it tests that outcome, or CPRT records its 1.1 id as moved to exactly one
# 2.0 subcategory and the check is a fair reading of that text. The other checks were removed; their lineage
# is the `legacy` data table at the end.

default compliant := false

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
	not input.detect.continuous_monitoring.network_monitored
	msg := "CSF DE.CM-01: Network not monitored to detect potential cybersecurity events"
}

violation contains msg if {
	not input.detect.continuous_monitoring.physical_environment_monitored
	msg := "CSF DE.CM-02: Physical environment not monitored for unauthorized access"
}

violation contains msg if {
	not input.detect.continuous_monitoring.external_provider_activity_monitored
	msg := "CSF DE.CM-06: External service provider activity not monitored"
}

compliant if count(violation) == 0

compliance_report := {
	"function": "DETECT",
	"controls_evaluated": 6,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

# Lineage of the CSF 1.1-era fact checks this module no longer evaluates (removed; data only, no rule
# behind it, not a control). Keyed by the label the check carried. status "retired": the CSF 1.1 id is
# withdrawn in CSF 2.0 (csf_2_0_ids = CPRT's destinations); "unmapped": the label reused a current CSF 2.0
# id but the check tested something else or only part of it. facts_read: the input the check read. Each 2.0
# subcategory is decided in nist.csf.main on its own basis (facts or attestation).
legacy := {
	"DE.AE-01": {
		"csf_1_1_id": "DE.AE-01",
		"status": "retired",
		"csf_2_0_ids": ["ID.AM-03"],
		"facts_read": ["input.detect.anomalies_events.baseline_established"],
		"legacy_message": "Baseline of network operations and expected data flows not established",
		"reason": "CSF 1.1 DE.AE-01 (\"A baseline of network operations and expected data flows for users and systems is established and managed\") is withdrawn in CSF 2.0: Incorporated into ID.AM-03; this check tests part of a broader CSF 2.0 outcome, so it cannot decide ID.AM-03 on its own",
	},
	"DE.AE-05": {
		"csf_1_1_id": "DE.AE-05",
		"status": "retired",
		"csf_2_0_ids": ["DE.AE-08"],
		"facts_read": ["input.detect.anomalies_events.alert_thresholds_established"],
		"legacy_message": "Incident alert thresholds not established",
		"reason": "CSF 1.1 DE.AE-05 (\"Incident alert thresholds are established\") is withdrawn in CSF 2.0: Moved to DE.AE-08; not carried because the check tests that incident alert thresholds are established; DE.AE-08 requires that incidents are declared when adverse events meet the defined criteria",
	},
	"DE.CM-03": {
		"csf_1_1_id": "DE.CM-03",
		"status": "unmapped",
		"csf_2_0_ids": ["DE.CM-03"],
		"facts_read": ["input.detect.continuous_monitoring.personnel_activity_monitored"],
		"legacy_message": "Personnel activity not monitored for anomalous behavior",
		"reason": "CSF 2.0 DE.CM-03 reads \"Personnel activity and technology usage are monitored to find potentially adverse events\"; this check tests personnel activity only; the 2.0 text also covers technology usage",
	},
	"DE.CM-04": {
		"csf_1_1_id": "DE.CM-04",
		"status": "retired",
		"csf_2_0_ids": ["DE.CM-01", "DE.CM-09"],
		"facts_read": ["input.detect.continuous_monitoring.malicious_code_detected"],
		"legacy_message": "Malicious code not detected via continuous scanning",
		"reason": "CSF 1.1 DE.CM-04 (\"Malicious code is detected\") is withdrawn in CSF 2.0: Incorporated into DE.CM-01, DE.CM-09; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"DE.CM-05": {
		"csf_1_1_id": "DE.CM-05",
		"status": "retired",
		"csf_2_0_ids": ["DE.CM-01", "DE.CM-09"],
		"facts_read": ["input.detect.continuous_monitoring.unauthorized_mobile_code_detected"],
		"legacy_message": "Unauthorized mobile code not detected",
		"reason": "CSF 1.1 DE.CM-05 (\"Unauthorized mobile code is detected\") is withdrawn in CSF 2.0: Incorporated into DE.CM-01, DE.CM-09; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"DE.CM-07": {
		"csf_1_1_id": "DE.CM-07",
		"status": "retired",
		"csf_2_0_ids": ["DE.CM-01", "DE.CM-03", "DE.CM-06", "DE.CM-09"],
		"facts_read": ["input.detect.continuous_monitoring.unauthorized_personnel_devices_monitored"],
		"legacy_message": "Monitoring for unauthorized personnel/connections/devices/software not performed",
		"reason": "CSF 1.1 DE.CM-07 (\"Monitoring for unauthorized personnel, connections, devices, and software is performed\") is withdrawn in CSF 2.0: Incorporated into DE.CM-01, DE.CM-03, DE.CM-06, DE.CM-09; this check its outcome is spread over 4 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
	"DE.CM-08": {
		"csf_1_1_id": "DE.CM-08",
		"status": "retired",
		"csf_2_0_ids": ["ID.RA-01"],
		"facts_read": ["input.detect.continuous_monitoring.vulnerability_scans_performed"],
		"legacy_message": "Vulnerability scans not performed",
		"reason": "CSF 1.1 DE.CM-08 (\"Vulnerability scans are performed\") is withdrawn in CSF 2.0: Incorporated into ID.RA-01; this check tests part of a broader CSF 2.0 outcome, so it cannot decide ID.RA-01 on its own",
	},
	"DE.DP-01": {
		"csf_1_1_id": "DE.DP-01",
		"status": "retired",
		"csf_2_0_ids": ["GV.RR-02"],
		"facts_read": ["input.detect.detection_processes.roles_defined"],
		"legacy_message": "Roles and responsibilities for detection not well-defined",
		"reason": "CSF 1.1 DE.DP-01 (\"Roles and responsibilities for detection are well defined to ensure accountability\") is withdrawn in CSF 2.0: Incorporated into GV.RR-02; this check tests part of a broader CSF 2.0 outcome, so it cannot decide GV.RR-02 on its own",
	},
	"DE.DP-02": {
		"csf_1_1_id": "DE.DP-02",
		"status": "retired",
		"csf_2_0_ids": ["DE.AE"],
		"facts_read": ["input.detect.detection_processes.activities_comply_with_requirements"],
		"legacy_message": "Detection activities don't comply with all applicable requirements",
		"reason": "CSF 1.1 DE.DP-02 (\"Detection activities comply with all applicable requirements\") is withdrawn in CSF 2.0: Incorporated into DE.AE; this check tests part of a broader CSF 2.0 outcome, so it cannot decide DE.AE on its own",
	},
	"DE.DP-03": {
		"csf_1_1_id": "DE.DP-03",
		"status": "retired",
		"csf_2_0_ids": ["ID.IM-02"],
		"facts_read": ["input.detect.detection_processes.detection_processes_tested"],
		"legacy_message": "Detection processes not tested",
		"reason": "CSF 1.1 DE.DP-03 (\"Detection processes are tested\") is withdrawn in CSF 2.0: Incorporated into ID.IM-02; this check tests part of a broader CSF 2.0 outcome, so it cannot decide ID.IM-02 on its own",
	},
	"DE.DP-04": {
		"csf_1_1_id": "DE.DP-04",
		"status": "retired",
		"csf_2_0_ids": ["DE.AE-06"],
		"facts_read": ["input.detect.detection_processes.event_information_communicated"],
		"legacy_message": "Event detection information not communicated",
		"reason": "CSF 1.1 DE.DP-04 (\"Event detection information is communicated\") is withdrawn in CSF 2.0: Incorporated into DE.AE-06; this check tests part of a broader CSF 2.0 outcome, so it cannot decide DE.AE-06 on its own",
	},
	"DE.DP-05": {
		"csf_1_1_id": "DE.DP-05",
		"status": "retired",
		"csf_2_0_ids": ["ID.IM", "ID.IM-03"],
		"facts_read": ["input.detect.detection_processes.detection_processes_improved"],
		"legacy_message": "Detection processes not continuously improved",
		"reason": "CSF 1.1 DE.DP-05 (\"Detection processes are continuously improved\") is withdrawn in CSF 2.0: Incorporated into ID.IM, ID.IM-03; this check its outcome is spread over 2 CSF 2.0 elements, so it cannot be attributed to one subcategory",
	},
}
