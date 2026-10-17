package cis.mobile.android_test

import rego.v1

# Report must stay fully populated when a check fails (validation 2026-10-17).

test_report_defined_on_empty_input if {
	r := data.cis.mobile.android.android_device_compliance with input as {}
	r.overall_compliant == false
	r.screen_lock_enabled == false
	count(r) == 32
}

test_report_defined_when_one_check_fails if {
	r := data.cis.mobile.android.android_device_compliance with input as {"device_config": {"screen_lock": {"enabled": false, "type": "pin", "timeout_minutes": 2}}}
	r.screen_lock_enabled == false
	r.auto_lock_timeout == true
	r.overall_compliant == false
}
