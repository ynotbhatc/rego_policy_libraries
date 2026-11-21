package ccpa.cybersecurity_audits_numeric_guards_test

import rego.v1

# "1" sorts above every number: a string consumer count met the 250,000 threshold; null sorted below it and
# let a not-applicable declaration pass unchecked. Both are now evidence missing.
test_string_consumer_count_is_evidence_missing if {
	vs := data.ccpa.cybersecurity_audits.violations with input as {"ccpa": {"cybersecurity_audits": {"applicable": false, "thresholds": {"meets_revenue_threshold": true, "consumers_processed_prior_year": "1", "sensitive_consumers_processed_prior_year": 10}}}}
	count(vs) == 1
	some v in vs
	contains(v, "evidence missing - thresholds.consumers_processed_prior_year")
}

test_null_consumer_count_is_evidence_missing if {
	vs := data.ccpa.cybersecurity_audits.violations with input as {"ccpa": {"cybersecurity_audits": {"applicable": false, "thresholds": {"meets_revenue_threshold": true, "consumers_processed_prior_year": null, "sensitive_consumers_processed_prior_year": 10}}}}
	some v in vs
	contains(v, "evidence missing - thresholds.consumers_processed_prior_year")
}

test_text_sensitive_count_is_evidence_missing if {
	vs := data.ccpa.cybersecurity_audits.violations with input as {"ccpa": {"cybersecurity_audits": {"applicable": false, "thresholds": {"meets_revenue_threshold": true, "consumers_processed_prior_year": 10, "sensitive_consumers_processed_prior_year": "x"}}}}
	some v in vs
	contains(v, "evidence missing - thresholds.sensitive_consumers_processed_prior_year")
}

test_numeric_counts_unchanged if {
	data.ccpa.cybersecurity_audits.compliant with input as {"ccpa": {"cybersecurity_audits": {"applicable": false, "thresholds": {"meets_revenue_threshold": true, "consumers_processed_prior_year": 1000, "sensitive_consumers_processed_prior_year": 10}}}}
	vs := data.ccpa.cybersecurity_audits.violations with input as {"ccpa": {"cybersecurity_audits": {"applicable": false, "thresholds": {"meets_revenue_threshold": true, "consumers_processed_prior_year": 300000, "sensitive_consumers_processed_prior_year": 10}}}}
	count(vs) == 1
	some v in vs
	contains(v, "§7120(b): business declares")
}
