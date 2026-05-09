package ccpa.data_practices

import rego.v1

violations contains msg if {
	not input.ccpa.data_practices.data_minimization.collected_only_for_disclosed_purposes
	msg := "CPRA §1798.100(a)(3): Personal information collected for purposes not disclosed to consumer"
}

violations contains msg if {
	not input.ccpa.data_practices.data_minimization.collection_limited_to_necessary
	msg := "CPRA §1798.100(a)(3): Personal information collection not limited to what is reasonably necessary"
}

violations contains msg if {
	not input.ccpa.data_practices.data_minimization.not_used_incompatibly
	msg := "CPRA §1798.100(a)(3): Personal information used in manner incompatible with disclosed purpose"
}

violations contains msg if {
	not input.ccpa.data_practices.purpose_limitation.not_used_beyond_disclosed_purposes
	msg := "CPRA §1798.100(a)(3): Personal information used for purposes materially different from those disclosed"
}

violations contains msg if {
	not input.ccpa.data_practices.purpose_limitation.not_sold_beyond_disclosed_categories
	msg := "CPRA §1798.100(a)(3): Personal information sold or shared beyond disclosed categories"
}

violations contains msg if {
	not input.ccpa.data_practices.retention_limitation.schedule_established_and_documented
	msg := "CPRA §1798.100(a)(3): Retention schedule for personal information not established or not documented"
}

violations contains msg if {
	not input.ccpa.data_practices.retention_limitation.not_retained_longer_than_necessary
	msg := "CPRA §1798.100(a)(3): Personal information retained longer than necessary for disclosed purpose"
}

violations contains msg if {
	not input.ccpa.data_practices.retention_limitation.automated_deletion_enforced
	msg := "CPRA §1798.100(a)(3): Retention schedule not technically enforced with automated deletion"
}

violations contains msg if {
	not input.ccpa.data_practices.security.reasonable_security_implemented
	msg := "CCPA §1798.150: Reasonable security measures not implemented for personal information"
}

violations contains msg if {
	not input.ccpa.data_practices.security.breach_notification_within_72_hours
	msg := "CCPA §1798.150: Security incidents not reported to CPPA within 72 hours"
}

violations contains msg if {
	not input.ccpa.data_practices.security.consumer_notification_without_unreasonable_delay
	msg := "CCPA §1798.150: Consumer notification after breach delayed unreasonably"
}

violations contains msg if {
	not input.ccpa.data_practices.data_protection_assessments.conducted_for_high_risk
	msg := "CPRA §1798.185(a)(15): Data Protection Assessments not conducted for high-risk processing (profiling, sensitive PI, sharing)"
}

violations contains msg if {
	not input.ccpa.data_practices.data_protection_assessments.submitted_to_cppa_on_request
	msg := "CPRA §1798.185(a)(15): Data Protection Assessments not available for submission to CPPA upon request"
}

violations contains msg if {
	not input.ccpa.data_practices.data_protection_assessments.reviewed_annually
	msg := "CPRA §1798.185(a)(15): Data Protection Assessments not reviewed annually"
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "CCPA/CPRA",
	"domain": "Data Practices (§1798.100, §1798.150, §1798.185)",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
