package pci_dss_tests.logging_monitoring.requirement_10_test
import rego.v1

import data.pci_dss.logging_monitoring.requirement_10 as r10

# Audit 2026-11-17 follow-up (SAQ D rows 10.4.1.1, 10.4.2.1, 10.5.1, 10.6.x).

test_10_4_1_1_automated_mechanism_passes_without_siem_flags if {
	r10.automated_log_analysis with input as {"pci": {"log_review": {"automated": {"enabled": true}}}}
}

test_10_4_1_1_missing_fails if not r10.automated_log_analysis with input as {}

_periodic(actual, defined) := {"pci": {"log_review": {"periodic": {"performed": true, "frequency_days": actual, "tra_defined_frequency_days": defined, "documented": true}}}}

test_10_4_2_1_tra_defined_monthly_passes if r10.periodic_log_review with input as _periodic(30, 30)

test_10_4_2_1_beyond_tra_frequency_fails if not r10.periodic_log_review with input as _periodic(30, 14)

test_10_4_2_1_tra_frequency_missing_fails if not r10.periodic_log_review with input as _periodic(7, null)

_retention(total, online) := {"pci": {"log_retention": {"total_months": total, "online_months": online, "policy": {"documented": true}}}}

test_10_5_1_twelve_and_three_months_pass_without_24h_flag if r10.log_retention with input as _retention(12, 3)

test_10_5_1_eleven_months_fails if not r10.log_retention with input as _retention(11, 3)

test_10_5_1_string_months_fail if not r10.log_retention with input as _retention("24", "6")

test_10_6_sync_passes_without_drift_value if {
	r10.time_synchronization with input as {"pci": {"time_sync": {
		"ntp": {"implemented": true}, "authoritative_time_source": {"used": true},
		"internal_servers": {"synced_from_authoritative": true}, "cde_systems": {"synchronized": true},
	}}}
}
