package governance.geisa.adm_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

good := {
	"manifest": {"applicationId": "app.demo"},
	"lwm2m": {
		"registered": true,
		"version": "1.1",
		"registered_objects": ["/9/0"],
		"object9": {"pkg_name": "app.demo", "update_state": 4, "update_result": 1, "activation_state": 1},
	},
}

test_adm_good_input_compliant if {
	data.governance.geisa.adm.compliant with input as good
}

test_adm_empty_object9_not_compliant if {
	i2 := {"manifest": good.manifest, "lwm2m": {"registered": true, "version": "1.1", "registered_objects": ["/9/0"], "object9": {}}}
	not data.governance.geisa.adm.compliant with input as i2
	v := data.governance.geisa.adm.violations with input as i2
	count(v) >= 3
}

test_adm_object9_missing_pkg_name_flagged if {
	o9 := {"update_state": 4, "update_result": 1, "activation_state": 1}
	i := {"manifest": good.manifest, "lwm2m": {"registered": true, "version": "1.1", "registered_objects": ["/9/0"], "object9": o9}}
	not data.governance.geisa.adm.compliant with input as i
}

test_adm_registered_objects_string_not_compliant if {
	i := {"manifest": good.manifest, "lwm2m": object.union(good.lwm2m, {"registered_objects": "none"})}
	not data.governance.geisa.adm.compliant with input as i
	v := data.governance.geisa.adm.violations with input as i
	"ADM: lwm2m.registered_objects missing or not an array" in v
}

test_adm_registered_objects_missing_not_compliant if {
	i := {"manifest": good.manifest, "lwm2m": {"registered": true, "version": "1.1", "object9": good.lwm2m.object9}}
	not data.governance.geisa.adm.compliant with input as i
}

test_adm_numeric_version_below_minimum_flagged if {
	i := {"manifest": good.manifest, "lwm2m": object.union(good.lwm2m, {"version": 1.0})}
	not data.governance.geisa.adm.compliant with input as i
	v := data.governance.geisa.adm.violations with input as i
	"ADM: LwM2M version must be >= 1.1, got '1'" in v
}

test_adm_numeric_version_ok if {
	i := {"manifest": good.manifest, "lwm2m": object.union(good.lwm2m, {"version": 1.2})}
	data.governance.geisa.adm.compliant with input as i
}

test_adm_version_missing_flagged if {
	i := {"manifest": good.manifest, "lwm2m": {"registered": true, "registered_objects": ["/9/0"], "object9": good.lwm2m.object9}}
	not data.governance.geisa.adm.compliant with input as i
}
