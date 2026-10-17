package iec_62443.fr6_test

import rego.v1

has(prefix, inp) if {
	v := data.iec_62443.fr6.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_absent_retention_flagged if has("IEC 62443 SR 6.1 (TRE): IACS audit logs are retained", {"target_sl": 2, "monitoring": {}})
test_short_retention_flagged if has("IEC 62443 SR 6.1 (TRE): IACS audit logs are retained", {"monitoring": {"ics_log_retention_days": 7}})
test_ok_retention_not_flagged if not has("IEC 62443 SR 6.1 (TRE): IACS audit logs are retained", {"monitoring": {"ics_log_retention_days": 120}})

test_absent_mttd_mttr_flagged_at_sl2 if {
	inp := {"target_sl": 2, "monitoring": {}}
	has("IEC 62443 SR 6.2 RE 1 SL2 (TRE): Mean time to detect", inp)
	has("IEC 62443 SR 6.2 RE 1 SL2 (TRE): Mean time to respond", inp)
}

test_slow_mttd_flagged if has("IEC 62443 SR 6.2 RE 1 SL2 (TRE): Mean time to detect", {"target_sl": 2, "monitoring": {"mean_time_to_detect_hours": 48}})

test_ok_mttd_mttr_not_flagged if {
	inp := {"target_sl": 2, "monitoring": {"mean_time_to_detect_hours": 2, "mean_time_to_respond_hours": 1}}
	not has("IEC 62443 SR 6.2 RE 1 SL2 (TRE): Mean time", inp)
}

test_sl1_does_not_require_mttd if not has("IEC 62443 SR 6.2 RE 1", {"target_sl": 1, "monitoring": {}})
