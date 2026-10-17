package iec_62443.fr2_test

import rego.v1

has(prefix, inp) if {
	v := data.iec_62443.fr2.violations with input as inp
	some x in v
	startswith(x, prefix)
}

sys(extra) := {"target_sl": 1, "ics_systems": [object.union({"name": "plc1"}, extra)]}

test_absent_lock_timeout_flagged if has("IEC 62443 SR 2.5 (UC): ICS system 'plc1' session lock timeout", sys({}))
test_long_lock_timeout_flagged if has("IEC 62443 SR 2.5 (UC): ICS system 'plc1' session lock timeout", sys({"session_lock_timeout_minutes": 60}))
test_ok_lock_timeout_not_flagged if not has("IEC 62443 SR 2.5 (UC): ICS system 'plc1' session lock timeout", sys({"session_lock_timeout_minutes": 10}))

test_absent_retention_flagged if has("IEC 62443 SR 2.9 (UC): IACS audit logs are retained", {"monitoring": {}})
test_short_retention_flagged if has("IEC 62443 SR 2.9 (UC): IACS audit logs are retained", {"monitoring": {"ics_log_retention_days": 30}})
test_ok_retention_not_flagged if not has("IEC 62443 SR 2.9 (UC): IACS audit logs are retained", {"monitoring": {"ics_log_retention_days": 365}})

test_sr_2_12_does_not_fail_sr_2_1 if {
	n := data.iec_62443.fr2.fr2_passing_srs with data.iec_62443.fr2.violations as {"IEC 62443 SR 2.12 SL2 (UC): x"}
	n == 11
}

test_sr_2_1_counted_failing if {
	n := data.iec_62443.fr2.fr2_passing_srs with data.iec_62443.fr2.violations as {"IEC 62443 SR 2.1 (UC): x"}
	n == 11
}
