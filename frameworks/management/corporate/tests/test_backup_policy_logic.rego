package corporate.backup_test

import rego.v1

import data.corporate.backup as b

# Validation 2026-10-17.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

sys(extra) := object.union({"id": "s1", "name": "Sys", "criticality_level": "standard", "data_types": ["operational"], "backup_config": {"frequency": "daily", "retention_policy": {"years": 3}, "last_restore_test": now_rfc}, "recovery_config": {"last_dr_test": now_rfc}}, extra)

test_personal_data_with_regulation_has_no_eval_conflict if {
	s := sys({"data_types": ["personal"], "regulatory_requirements": ["GDPR"], "backup_config": {"retention_policy": {"years": 3}}})
	v := b.retention_violations with input as {"systems": [s]}
	count(v) == 0
}

test_strictest_regulation_wins if {
	s := sys({"data_types": ["personal"], "regulatory_requirements": ["GDPR", "SOX"], "backup_config": {"retention_policy": {"years": 3}}})
	v1 := b.retention_violations with input as {"systems": [s]}
	count(v1) == 1
	s7 := sys({"data_types": ["personal"], "regulatory_requirements": ["GDPR", "SOX"], "backup_config": {"retention_policy": {"years": 7}}})
	v2 := b.retention_violations with input as {"systems": [s7]}
	count(v2) == 0
}

test_sox_personal_data_not_adequate_on_operational_minimum if {
	s := sys({"data_types": ["operational", "personal"], "regulatory_requirements": ["SOX"], "backup_config": {"retention_policy": {"years": 3}}})
	v3 := b.retention_violations with input as {"systems": [s]}
	count(v3) == 1
}

test_financial_system_violation_message_builds if {
	s := sys({"data_types": ["financial"], "backup_config": {"retention_policy": {"years": 2}}})
	v := b.retention_violations with input as {"systems": [s]}
	count(v) == 1
	v[0].required_retention == "7 years minimum"
}

test_missing_data_types_not_adequate if {
	s := json.remove(sys({}), ["data_types"])
	not b.retention_periods_meet_requirements with input as {"systems": [s]}
}

test_missing_test_success_rate_fails if {
	s := sys({})
	not b.test_success_rates_adequate with input as {"systems": [s]}
	ok := sys({"backup_config": {"test_success_rate": 99}})
	b.test_success_rates_adequate with input as {"systems": [ok]}
}

test_iso_dr_test_date_current_and_violation_listed_when_old if {
	s := sys({"recovery_config": {"last_dr_test": now_rfc}})
	b.recovery_procedures_tested with input as {"systems": [s]}
	old := sys({"recovery_config": {"last_dr_test": "2019-01-01T00:00:00Z"}})
	not b.recovery_procedures_tested with input as {"systems": [old]}
	v := b.recovery_violations with input as {"systems": [old]}
	count(v) == 1
	v[0].days_overdue > 365
}

test_missing_dr_date_still_listed if {
	s := json.remove(sys({}), ["recovery_config/last_dr_test"])
	v := b.recovery_violations with input as {"systems": [s]}
	count(v) == 1
	v[0].days_overdue == "unknown"
}

test_pci_only_cardholder_systems_in_scope if {
	systems := [
		{"id": "c", "data_types": ["cardholder_data"], "backup_config": {"encryption": {"enabled": true}, "access_controls": {"mfa_required": true}}},
		{"id": "n", "data_types": ["operational"]},
	]
	b.pci_dss_backup_compliant with input as {"systems": systems} with b.backup_compliant as true
}

test_sox_only_financial_systems_in_scope if {
	systems := [
		{"id": "f", "data_types": ["financial"], "backup_config": {"retention_policy": {"years": 7}}, "recovery_config": {"last_dr_test": now_rfc}, "criticality_level": "standard"},
		{"id": "n", "data_types": ["operational"]},
	]
	b.sox_backup_compliant with input as {"systems": systems} with b.backup_compliant as true
}

test_performance_score_defined_for_empty_systems if {
	b.backup_performance_score == 0 with input as {"systems": []}
	b.backup_performance_score == 0 with input as {}
}
