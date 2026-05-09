package ccpa.consumer_rights

import rego.v1

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_know.categories_disclosed
	msg := "CCPA §1798.110: Categories of personal information collected, purposes, and third parties not disclosed"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_know.specific_pieces_provided
	msg := "CCPA §1798.115: Specific pieces of personal information not provided to consumer upon request"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_know.response_within_45_days
	msg := "CCPA §1798.100: Response to right-to-know request not fulfilled within 45 days"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_know.two_requests_per_year_honored
	msg := "CCPA §1798.100: Two disclosure requests per 12-month period not honored"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_know.identity_verification_established
	msg := "CCPA §1798.100: Identity verification process for right-to-know requests not established"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_delete.deletion_process_established
	msg := "CCPA §1798.105: Deletion process for personal information not established"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_delete.deletion_propagated
	msg := "CCPA §1798.105: Deletion not propagated to service providers and contractors"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_delete.exceptions_documented
	msg := "CCPA §1798.105: Exceptions to deletion (legal obligation, security) not documented"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_delete.confirmation_provided
	msg := "CCPA §1798.105: Confirmation of deletion not provided to consumer"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_opt_out.do_not_sell_link_on_homepage
	msg := "CCPA §1798.135: 'Do Not Sell or Share My Personal Information' link not present on homepage"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_opt_out.honored_within_15_business_days
	msg := "CCPA §1798.120: Opt-out of sale or sharing not honored within 15 business days"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_opt_out.no_reenrollment_within_12_months
	msg := "CCPA §1798.120: Opted-out consumers re-enrolled for sale or sharing within 12 months without consent"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_opt_out.gpc_signal_honored
	msg := "CCPA §1798.135: Global Privacy Control (GPC) signal not honored"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_correct.correction_process_defined
	msg := "CPRA §1798.106: Process for consumers to correct inaccurate personal information not defined"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_correct.correction_propagated
	msg := "CPRA §1798.106: Correction not propagated to third parties"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_correct.response_within_45_days
	msg := "CPRA §1798.106: Response to right-to-correct request not fulfilled within 45 days"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_limit_sensitive.limit_sensitive_pi_link_available
	msg := "CPRA §1798.121: 'Limit the Use of My Sensitive Personal Information' link not available"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_limit_sensitive.use_limited_when_requested
	msg := "CPRA §1798.121: Sensitive personal information use not limited to specified purposes when consumer requests"
}

violations contains msg if {
	not input.ccpa.consumer_rights.right_to_limit_sensitive.honored_within_15_business_days
	msg := "CPRA §1798.121: Request to limit sensitive personal information use not honored within 15 business days"
}

violations contains msg if {
	not input.ccpa.consumer_rights.non_discrimination.no_penalty_for_rights_exercise
	msg := "CCPA §1798.125: Consumers penalized for exercising privacy rights"
}

violations contains msg if {
	not input.ccpa.consumer_rights.non_discrimination.no_different_pricing_for_opt_out
	msg := "CCPA §1798.125: Consumers denied goods, services, or charged different prices for opting out"
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "CCPA/CPRA",
	"domain": "Consumer Rights (§1798.100–§1798.125)",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
