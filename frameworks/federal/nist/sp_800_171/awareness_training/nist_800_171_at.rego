# METADATA
# title: "NIST SP 800-171 Rev 3 - Awareness and Training (AT) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 6
#     cited: 2
#     expected: 2
#     found: 6
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.awareness_training

import rego.v1

# NIST SP 800-171 Rev 3 - Awareness and Training (AT) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.02 Awareness and Training — Protecting Controlled Unclassified Information (CUI)

# 03.02.01 Literacy Training and Awareness (Rev 2 3.2.1): Ensure personnel are aware of security risks associated with their activities and
#         organizational systems, and ensure personnel are trained to carry out assigned
#         information security responsibilities
default security_awareness_program := false

security_awareness_program if {
	input.nist_800_171.awareness_training.awareness.program_established == true
	input.nist_800_171.awareness_training.awareness.all_personnel_covered == true
	input.nist_800_171.awareness_training.awareness.risk_topics_included == true
	input.nist_800_171.awareness_training.awareness.periodic_refreshes == true
}

# 03.02.02 Role-Based Training (Rev 2 3.2.2): Ensure personnel are trained to carry out assigned information security responsibilities
default role_based_training := false

role_based_training if {
	input.nist_800_171.awareness_training.role_training.role_specific_content == true
	input.nist_800_171.awareness_training.role_training.completion_tracked == true
	input.nist_800_171.awareness_training.role_training.before_access_granted == true
}

# 03.02.01 (Rev 2 3.2.3, withdrawn in Rev 3: Incorporated into 03.02.01.): Provide security awareness training on recognizing and reporting threats including
#         phishing, social engineering, and insider threats
default threat_recognition_training := false

threat_recognition_training if {
	input.nist_800_171.awareness_training.threat_training.phishing_covered == true
	input.nist_800_171.awareness_training.threat_training.social_engineering_covered == true
	input.nist_800_171.awareness_training.threat_training.insider_threat_covered == true
	input.nist_800_171.awareness_training.threat_training.reporting_procedures_covered == true
}

# Violations set
violations contains msg if {
	not security_awareness_program
	msg := "NIST SP 800-171 03.02.01: A security awareness program covering CUI-related risks must be established for all personnel"
}

violations contains msg if {
	not role_based_training
	msg := "NIST SP 800-171 03.02.02: Role-based security training must be provided before granting access and tracked to completion"
}

violations contains msg if {
	not threat_recognition_training
	msg := "NIST SP 800-171 03.02.01 (Rev 2 3.2.3, withdrawn in Rev 3: Incorporated into 03.02.01.): Security awareness training must cover phishing, social engineering, insider threats, and reporting procedures"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.02 Awareness and Training",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 2,
	"violations": violations,
	"compliant": compliant,
	"controls": {
		"03.02.01_security_awareness_program": security_awareness_program,
		"03.02.02_role_based_training": role_based_training,
		"03.02.01_threat_recognition_training": threat_recognition_training,
	},
}
