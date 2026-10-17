package finops.tagging_fixes_test

import rego.v1

ft := data.finops.tagging

tags := {"team": "platform", "environment": "prod", "cost-center": "CC-1234", "owner": "a@example.com", "project": "p"}

res(id, extra) := {"id": id, "name": id, "type": "aws_instance", "tags": object.union(tags, extra)}

has_prefix_msg(vs, p) if {
	some v in vs
	contains(v, p)
}

test_calendar_invalid_date_flagged_invalid if {
	inp := {"resources": [res("web-1", {"expiry-date": "2025-13-45"})]}
	has_prefix_msg(ft.violations, "is invalid") with input as inp
}

test_valid_future_date_not_flagged if {
	inp := {"resources": [res("web-1", {"expiry-date": "9999-12-31"})]}
	not has_prefix_msg(ft.violations, "Expiry:") with input as inp
}

test_malformed_date_flagged_invalid if {
	inp := {"resources": [res("web-1", {"expiry-date": "12/31/2030"})]}
	has_prefix_msg(ft.violations, "is invalid") with input as inp
}

test_past_date_still_flagged if {
	inp := {"resources": [res("web-1", {"expiry-date": "2020-01-01"})]}
	has_prefix_msg(ft.violations, "is in the past") with input as inp
}

test_zero_budget_overspend_reported if {
	inp := {"resources": [res("web-1", {})], "budget_registry": {"CC-1234": 0}, "current_spend": {"CC-1234": 50}}
	has_prefix_msg(ft.violations, "no budget allocated") with input as inp
	not ft.compliant with input as inp
}

test_zero_budget_no_spend_ok if {
	inp := {"resources": [res("web-1", {})], "budget_registry": {"CC-1234": 0}, "current_spend": {"CC-1234": 0}}
	not has_prefix_msg(ft.violations, "Budget:") with input as inp
}

test_normal_overspend_still_reports_percentage if {
	inp := {"resources": [res("web-1", {})], "budget_registry": {"CC-1234": 100}, "current_spend": {"CC-1234": 150}}
	has_prefix_msg(ft.violations, "(50% over)") with input as inp
}

# A violation on web-10 must not mark web-1 as non-compliant.
test_resource_id_prefix_not_confused if {
	inp := {"resources": [res("web-1", {}), object.remove(res("web-10", {}), ["tags"])]}
	r := ft.compliance_report with input as inp
	r.total_resources == 2
	r.compliant_resources == 1
	r.tagging_score == 50
}

test_leap_day_valid if {
	inp := {"resources": [res("web-1", {"expiry-date": "2096-02-29"})]}
	not has_prefix_msg(ft.violations, "is invalid") with input as inp
}

test_non_leap_feb_29_invalid if {
	inp := {"resources": [res("web-1", {"expiry-date": "2095-02-29"})]}
	has_prefix_msg(ft.violations, "is invalid") with input as inp
}

test_april_31_invalid if {
	inp := {"resources": [res("web-1", {"expiry-date": "2100-04-31"})]}
	has_prefix_msg(ft.violations, "is invalid") with input as inp
}

test_month_zero_invalid if {
	inp := {"resources": [res("web-1", {"expiry-date": "2100-00-10"})]}
	has_prefix_msg(ft.violations, "is invalid") with input as inp
}

# A resource with no explicit `billable` field is billable by default.
test_missing_billable_field_still_requires_tags if {
	inp := {"resources": [{"id": "web-2", "name": "web-2", "type": "aws_instance", "tags": {"team": "platform"}}]}
	has_prefix_msg(ft.violations, "missing required tag") with input as inp
}

test_billable_false_exempt_from_required_tags if {
	inp := {"resources": [{"id": "web-3", "name": "web-3", "type": "aws_instance", "billable": false, "tags": {"team": "platform"}}]}
	not has_prefix_msg(ft.violations, "missing required tag") with input as inp
}

test_budget_message_is_not_garbled_for_integers if {
	inp := {"resources": [res("web-1", {})], "budget_registry": {"CC-1234": 100}, "current_spend": {"CC-1234": 150}}
	has_prefix_msg(ft.violations, "spend $150 exceeds budget $100 (50% over)") with input as inp
}
