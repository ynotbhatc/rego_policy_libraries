package nerc_cip.cip_013_test

import rego.v1

import data.nerc_cip.cip_013 as c

# Decisions 2026-10-19: dates may be ISO-8601 (documented) or epoch ns.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

vendor_input(d) := {
	"vendors": [{"vendor_id": "v1", "criticality_level": "high"}],
	"vendor_risk_assessments": {"v1": {
		"completed": true,
		"completion_date": d,
		"risks_identified": true,
		"mitigation_plan_exists": true,
	}},
}

test_iso_vendor_assessment_date_is_current if {
	c.vendor_risk_assessments_performed with input as vendor_input(now_rfc)
}

test_ns_vendor_assessment_date_is_current if {
	c.vendor_risk_assessments_performed with input as vendor_input(time.now_ns())
}

test_old_iso_vendor_assessment_date_fails if {
	not c.vendor_risk_assessments_performed with input as vendor_input("2015-01-01T00:00:00Z")
}

test_iso_plan_review_date_is_current if {
	c.supply_chain_plan_review_current with input as {"supply_chain_plan": {"last_review_date": now_rfc}}
}
