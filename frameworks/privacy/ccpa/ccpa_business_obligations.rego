package ccpa.business_obligations

import rego.v1

violations contains msg if {
	not input.ccpa.business_obligations.privacy_policy.published_and_updated_annually
	msg := "CCPA §1798.130: Comprehensive privacy policy not published or not updated annually"
}

violations contains msg if {
	not input.ccpa.business_obligations.privacy_policy.lists_categories_collected
	msg := "CCPA §1798.130: Privacy policy does not list categories of personal information collected in prior 12 months"
}

violations contains msg if {
	not input.ccpa.business_obligations.privacy_policy.lists_collection_purposes
	msg := "CCPA §1798.130: Privacy policy does not list purposes for which personal information is collected"
}

violations contains msg if {
	not input.ccpa.business_obligations.privacy_policy.lists_third_party_categories
	msg := "CCPA §1798.130: Privacy policy does not list categories of third parties personal information is shared with"
}

violations contains msg if {
	not input.ccpa.business_obligations.privacy_policy.contact_information_included
	msg := "CCPA §1798.130: Privacy policy does not include contact information for privacy requests"
}

violations contains msg if {
	not input.ccpa.business_obligations.privacy_policy.ccpa_rights_disclosure_included
	msg := "CCPA §1798.130: Privacy policy does not include disclosure of CCPA consumer rights"
}

violations contains msg if {
	not input.ccpa.business_obligations.notice_at_collection.provided_at_or_before_collection
	msg := "CCPA §1798.100(b): Notice not provided at or before point of personal information collection"
}

violations contains msg if {
	not input.ccpa.business_obligations.notice_at_collection.categories_and_purposes_disclosed
	msg := "CCPA §1798.100(b): Categories of personal information and purposes not disclosed in notice at collection"
}

violations contains msg if {
	not input.ccpa.business_obligations.notice_at_collection.sale_sharing_disclosed_with_opt_out
	msg := "CCPA §1798.100(b): Sale or sharing of personal information not disclosed with opt-out link where applicable"
}

violations contains msg if {
	not input.ccpa.business_obligations.notice_at_collection.retention_periods_disclosed
	msg := "CCPA §1798.100(b): Retention periods or criteria for determination not disclosed in notice at collection"
}

violations contains msg if {
	not input.ccpa.business_obligations.training.personnel_trained
	msg := "CCPA §1798.135(b): Personnel handling privacy requests not trained on CCPA requirements"
}

violations contains msg if {
	not input.ccpa.business_obligations.training.training_documented_and_refreshed
	msg := "CCPA §1798.135(b): Privacy training not documented or not refreshed annually"
}

violations contains msg if {
	not input.ccpa.business_obligations.record_keeping.requests_retained_24_months
	msg := "CPRA §1798.185(a)(3): Records of privacy requests and responses not retained for 24 months"
}

violations contains msg if {
	not input.ccpa.business_obligations.record_keeping.annual_metrics_reported
	msg := "CPRA §1798.185(a)(3): Annual metrics on rights requests not reported (required for large businesses)"
}

violations contains msg if {
	not input.ccpa.business_obligations.service_provider_contracts.written_contracts_limiting_use
	msg := "CCPA §1798.140: Written contracts with service providers not in place limiting use of personal information"
}

violations contains msg if {
	not input.ccpa.business_obligations.service_provider_contracts.prohibition_on_selling
	msg := "CCPA §1798.140: Service provider contracts do not prohibit selling of personal information"
}

violations contains msg if {
	not input.ccpa.business_obligations.service_provider_contracts.subprocessor_restrictions
	msg := "CCPA §1798.140: Subprocessor restrictions not included in service provider contracts"
}

violations contains msg if {
	input.ccpa.business_obligations.data_broker.applicable
	not input.ccpa.business_obligations.data_broker.registered_with_cppa
	msg := "CPRA §1798.99.80: Business qualifies as data broker but is not registered with the California Privacy Protection Agency"
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "CCPA/CPRA",
	"domain": "Business Obligations (§1798.130–§1798.185)",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
