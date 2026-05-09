package iso27701.data_subject_rights

import rego.v1

violations contains msg if {
	not input.iso27701.data_subject_rights.access.process_defined
	msg := "ISO 27701 Annex B / GDPR Art. 15: Right of access process not defined"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.access.thirty_day_sla
	msg := "ISO 27701 Annex B / GDPR Art. 15: Right of access response SLA of 30 days not established"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.rectification.process_defined
	msg := "ISO 27701 Annex B / GDPR Art. 16: Right to rectification process not defined"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.rectification.propagated_to_processors
	msg := "ISO 27701 Annex B / GDPR Art. 16: Rectification not propagated to processors and third parties"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.erasure.technical_deletion_capability
	msg := "ISO 27701 Annex B / GDPR Art. 17: Technical capability for deletion of PII not implemented"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.erasure.backups_addressed
	msg := "ISO 27701 Annex B / GDPR Art. 17: Right to erasure process does not address backup copies"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.restriction.flag_based_mechanism
	msg := "ISO 27701 Annex B / GDPR Art. 18: Flag-based processing restriction mechanism not implemented"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.portability.machine_readable_format
	msg := "ISO 27701 Annex B / GDPR Art. 20: Data portability in machine-readable format not available"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.portability.direct_transfer_supported
	msg := "ISO 27701 Annex B / GDPR Art. 20: Direct transfer of PII to another controller not supported"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.objection.opt_out_mechanism
	msg := "ISO 27701 Annex B / GDPR Art. 21: Opt-out mechanism for processing objection not implemented"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.objection.direct_marketing_always_honored
	msg := "ISO 27701 Annex B / GDPR Art. 21: Objection to direct marketing not always honored unconditionally"
}

violations contains msg if {
	not input.iso27701.data_subject_rights.automated_decisions.human_review_available
	msg := "ISO 27701 Annex B / GDPR Art. 22: Human review not available for automated decision-making"
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "ISO/IEC 27701:2019",
	"domain": "Annex B — GDPR Data Subject Rights Mapping",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
