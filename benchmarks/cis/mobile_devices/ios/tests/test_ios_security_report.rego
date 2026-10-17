package cis.mobile.ios_test

import rego.v1

# Report must stay fully populated when a check fails (validation 2026-10-17).

test_report_defined_on_empty_input if {
	r := data.cis.mobile.ios.ios_device_compliance with input as {}
	r.overall_compliant == false
	r.passcode_enabled == false
	count(r) == 25
}

test_report_defined_when_passcode_check_fails if {
	r := data.cis.mobile.ios.ios_device_compliance with input as {"device_config": {"passcode_enabled": false, "limit_ad_tracking": true}}
	r.passcode_enabled == false
	r.advertising_tracking_disabled == true
	r.overall_compliant == false
}
