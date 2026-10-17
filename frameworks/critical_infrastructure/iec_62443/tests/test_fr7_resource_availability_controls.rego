package iec_62443.fr7_test

import rego.v1

has(prefix, inp) if {
	v := data.iec_62443.fr7.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_absent_backup_frequency_flagged if has("IEC 62443 SR 7.3 (RA): IACS backups are performed every", {"backups": {}})
test_infrequent_backup_flagged if has("IEC 62443 SR 7.3 (RA): IACS backups are performed every", {"backups": {"backup_frequency_days": 30}})
test_weekly_backup_ok if not has("IEC 62443 SR 7.3 (RA): IACS backups are performed every", {"backups": {"backup_frequency_days": 7}})

test_absent_rto_high_criticality_flagged if has("IEC 62443 SR 7.4 (RA): High-criticality ICS system 'p'", {"ics_systems": [{"name": "p", "criticality": "high"}]})
test_long_rto_flagged if has("IEC 62443 SR 7.4 (RA): High-criticality ICS system 'p'", {"ics_systems": [{"name": "p", "criticality": "high", "recovery_time_objective_hours": 72}]})
test_ok_rto_not_flagged if not has("IEC 62443 SR 7.4 (RA): High-criticality ICS system 'p'", {"ics_systems": [{"name": "p", "criticality": "high", "recovery_time_objective_hours": 4}]})
test_low_criticality_without_rto_not_flagged if not has("IEC 62443 SR 7.4 (RA): High-criticality", {"ics_systems": [{"name": "p", "criticality": "low"}]})
