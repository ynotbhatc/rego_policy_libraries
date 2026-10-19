package nerc_cip.cip_012_test

import rego.v1

import data.nerc_cip.cip_012 as c

# decisions 2026-10-19: the 35-day log review gates compliant and yields a violation.

test_stale_log_review_violation if {
	i := {"communication_monitoring": {"last_review_date": "2019-01-01T00:00:00Z"}}
	not c.communication_log_review with input as i
	count([v | some v in c.violations with input as i; contains(v.description, "35 days")]) == 1
	not c.compliant with input as i
}

test_recent_log_review_passes if {
	now := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])
	c.communication_log_review with input as {"communication_monitoring": {"last_review_date": now}}
}

test_missing_log_review_violation if {
	count([v | some v in c.violations with input as {}; contains(v.description, "35 days")]) == 1
}
