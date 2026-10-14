# METADATA
# title: "NIST SP 800-171 Rev 3 - Incident Response (IR) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 6
#     cited: 3
#     expected: 3
#     found: 6
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.incident_response

import rego.v1

# NIST SP 800-171 Rev 3 - Incident Response (IR) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.06 Incident Response — Protecting Controlled Unclassified Information (CUI)

# 03.06.01 Incident Handling (Rev 2 3.6.1): Establish an operational incident-handling capability for organizational systems
#         including preparation, detection, analysis, containment, recovery, and user response
default incident_handling_capability := false

incident_handling_capability if {
	input.nist_800_171.incident_response.handling.plan_documented == true
	input.nist_800_171.incident_response.handling.preparation_phase == true
	input.nist_800_171.incident_response.handling.detection_procedures == true
	input.nist_800_171.incident_response.handling.analysis_procedures == true
	input.nist_800_171.incident_response.handling.containment_procedures == true
	input.nist_800_171.incident_response.handling.recovery_procedures == true
	input.nist_800_171.incident_response.handling.user_response_procedures == true
}

# 03.06.02 Incident Monitoring, Reporting, and Response Assistance (Rev 2 3.6.2): Track, document, and report incidents to appropriate officials and/or authorities
default incident_tracking_reporting := false

incident_tracking_reporting if {
	input.nist_800_171.incident_response.tracking.incident_tracking_system == true
	input.nist_800_171.incident_response.tracking.documentation_required == true
	input.nist_800_171.incident_response.tracking.designated_officials_identified == true
	input.nist_800_171.incident_response.tracking.reporting_timelines_defined == true
}

# 03.06.03 Incident Response Testing (Rev 2 3.6.3): Test the organizational incident response capability (tabletop exercise or live drill)
#         at least annually
default incident_response_testing := false

incident_response_testing if {
	input.nist_800_171.incident_response.testing.tested_annually == true
	input.nist_800_171.incident_response.testing.test_type_documented == true
	input.nist_800_171.incident_response.testing.results_reviewed == true
	input.nist_800_171.incident_response.testing.lessons_incorporated == true
}

# Violations set
violations contains msg if {
	not incident_handling_capability
	msg := "NIST SP 800-171 03.06.01: An operational incident-handling capability must be established covering preparation, detection, analysis, containment, recovery, and user response"
}

violations contains msg if {
	not incident_tracking_reporting
	msg := "NIST SP 800-171 03.06.02: Incidents must be tracked, documented, and reported to designated officials with defined reporting timelines"
}

violations contains msg if {
	not incident_response_testing
	msg := "NIST SP 800-171 03.06.03: Incident response capability must be tested at least annually with results reviewed and lessons incorporated"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.06 Incident Response",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 3,
	"violations": violations,
	"compliant": compliant,
	"controls": {
		"03.06.01_incident_handling_capability": incident_handling_capability,
		"03.06.02_incident_tracking_reporting": incident_tracking_reporting,
		"03.06.03_incident_response_testing": incident_response_testing,
	},
}
