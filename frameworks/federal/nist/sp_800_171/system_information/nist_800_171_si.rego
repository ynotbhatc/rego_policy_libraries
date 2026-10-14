# METADATA
# title: "NIST SP 800-171 Rev 3 - System and Information Integrity (SI) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 11
#     cited: 4
#     expected: 4
#     found: 11
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.system_information

import rego.v1

# NIST SP 800-171 Rev 3 - System and Information Integrity (SI) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.14 System and Information Integrity — Protecting Controlled Unclassified Information (CUI)

# 03.14.01 Flaw Remediation (Rev 2 3.14.1): Identify, report, and correct information and system flaws in a timely manner
default flaw_remediation := false

flaw_remediation if {
	input.nist_800_171.system_information.flaws.identification_process == true
	input.nist_800_171.system_information.flaws.reporting_process == true
	input.nist_800_171.system_information.flaws.timely_correction == true
	input.nist_800_171.system_information.flaws.tracking_system == true
}

# 03.14.02 Malicious Code Protection (Rev 2 3.14.2): Provide protection from malicious code at appropriate locations within
#          organizational systems
default malicious_code_protection := false

malicious_code_protection if {
	input.nist_800_171.system_information.malicious_code.protection_at_entry_exit == true
	input.nist_800_171.system_information.malicious_code.workstation_protection == true
	input.nist_800_171.system_information.malicious_code.server_protection == true
	input.nist_800_171.system_information.malicious_code.approved_solution == true
}

# 03.14.03 Security Alerts, Advisories, and Directives (Rev 2 3.14.3): Monitor system security alerts and advisories and take appropriate actions
#          in response
default security_alerts_monitored := false

security_alerts_monitored if {
	input.nist_800_171.system_information.alerts.monitoring_implemented == true
	input.nist_800_171.system_information.alerts.advisories_tracked == true
	input.nist_800_171.system_information.alerts.response_procedures_defined == true
	input.nist_800_171.system_information.alerts.subscribed_to_threat_feeds == true
}

# 03.14.02 (Rev 2 3.14.4, withdrawn in Rev 3: Incorporated into 03.14.02.): Update malicious code protection mechanisms when new releases are available
default malicious_code_updated := false

malicious_code_updated if {
	input.nist_800_171.system_information.malicious_code_updates.automatic_updates == true
	input.nist_800_171.system_information.malicious_code_updates.update_frequency_defined == true
	input.nist_800_171.system_information.malicious_code_updates.all_systems_covered == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.14.5, withdrawn in Rev 3: Addressed by 03.14.02.): Perform periodic scans of organizational systems and real-time scans of files
#          from external sources as files are downloaded, opened, or executed
default system_scanning := false

system_scanning if {
	input.nist_800_171.system_information.scanning.periodic_scans_performed == true
	input.nist_800_171.system_information.scanning.real_time_scanning == true
	input.nist_800_171.system_information.scanning.external_source_files_scanned == true
	input.nist_800_171.system_information.scanning.scan_schedule_defined == true
}

# 03.14.06 System Monitoring (Rev 2 3.14.6): Monitor organizational systems, including inbound and outbound communications
#          traffic, to detect attacks and indicators of potential attacks
default attack_detection_monitoring := false

attack_detection_monitoring if {
	input.nist_800_171.system_information.attack_detection.system_monitoring == true
	input.nist_800_171.system_information.attack_detection.inbound_traffic_monitored == true
	input.nist_800_171.system_information.attack_detection.outbound_traffic_monitored == true
	input.nist_800_171.system_information.attack_detection.ioc_detection == true
}

# 03.14.06 (Rev 2 3.14.7, withdrawn in Rev 3: Incorporated into 03.14.06.): Identify unauthorized use of organizational systems
default unauthorized_use_detection := false

unauthorized_use_detection if {
	input.nist_800_171.system_information.unauthorized_use.detection_mechanisms == true
	input.nist_800_171.system_information.unauthorized_use.baseline_established == true
	input.nist_800_171.system_information.unauthorized_use.anomaly_detection == true
	input.nist_800_171.system_information.unauthorized_use.response_procedures == true
}

# Violations set
violations contains msg if {
	not flaw_remediation
	msg := "NIST SP 800-171 03.14.01: System flaws must be identified, reported, and corrected in a timely manner with a tracking system"
}

violations contains msg if {
	not malicious_code_protection
	msg := "NIST SP 800-171 03.14.02: Malicious code protection must be deployed at entry/exit points, workstations, and servers using approved solutions"
}

violations contains msg if {
	not security_alerts_monitored
	msg := "NIST SP 800-171 03.14.03: Security alerts and advisories must be monitored with subscriptions to threat feeds and defined response procedures"
}

violations contains msg if {
	not malicious_code_updated
	msg := "NIST SP 800-171 03.14.02 (Rev 2 3.14.4, withdrawn in Rev 3: Incorporated into 03.14.02.): Malicious code protection mechanisms must be automatically updated on a defined schedule for all systems"
}

violations contains msg if {
	not attack_detection_monitoring
	msg := "NIST SP 800-171 03.14.06: Systems and inbound/outbound communications traffic must be monitored to detect attacks and indicators of compromise"
}

violations contains msg if {
	not unauthorized_use_detection
	msg := "NIST SP 800-171 03.14.06 (Rev 2 3.14.7, withdrawn in Rev 3: Incorporated into 03.14.06.): Unauthorized use of organizational systems must be detected through baseline monitoring, anomaly detection, and response procedures"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.14 System and Information Integrity",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 4,
	"violations": violations,
	"compliant": compliant,
	"retired_rev2_checks": {"rev2_3.14.5_system_scanning": system_scanning},
	"controls": {
		"03.14.01_flaw_remediation": flaw_remediation,
		"03.14.02_malicious_code_protection": malicious_code_protection,
		"03.14.03_security_alerts_monitored": security_alerts_monitored,
		"03.14.02_malicious_code_updated": malicious_code_updated,
		"03.14.06_attack_detection_monitoring": attack_detection_monitoring,
		"03.14.06_unauthorized_use_detection": unauthorized_use_detection,
	},
}
