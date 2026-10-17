package digital_sovereignty.breach_notification_sovereignty_fixes_test

import rego.v1

bn := data.digital_sovereignty.breach_notification_sovereignty

has_control(vs, c) if {
	some v in vs
	v.control == c
}

test_missing_timeline_still_reports_bn001 if has_control(bn.violations, "BN-001") with input as {"breach_notification": {}}

test_missing_early_warning_still_reports_bn002 if has_control(bn.violations, "BN-002") with input as {"breach_notification": {}}

test_missing_vendor_country_still_reports_bn005 if has_control(bn.violations, "BN-005") with input as {"breach_notification": {}}

test_missing_forensic_jurisdiction_still_reports_bn008 if has_control(bn.violations, "BN-008") with input as {"approved_jurisdictions": ["DE"], "breach_notification": {}}

test_violations_defined_on_empty_input_cover_every_failed_control if {
	count(bn.violations) == 10 with input as {}
}

test_non_numeric_timeline_is_reported_without_error if {
	has_control(bn.violations, "BN-001") with input as {"breach_notification": {"notification_timeline_hours": "soon"}}
}

test_null_timeline_not_compliant if not bn.notification_timeline_compliant with input as {"breach_notification": {"notification_timeline_hours": null}}

test_timeline_72_ok if bn.notification_timeline_compliant with input as {"breach_notification": {"notification_timeline_hours": 72}}

test_timeline_over_72_violates_with_value if {
	some v in bn.violations with input as {"breach_notification": {"notification_timeline_hours": 96}}
	v.control == "BN-001"
	contains(v.description, "96")
}

test_null_early_warning_not_compliant if not bn.early_warning_timeline_compliant with input as {"breach_notification": {"early_warning_timeline_hours": null}}
