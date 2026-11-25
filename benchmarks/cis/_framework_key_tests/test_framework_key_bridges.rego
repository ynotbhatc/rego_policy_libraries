package cis_framework_key_bridges_test

# Regression guard for the framework-key entrypoint contract.
#
# Each framework exposes a stable, key-addressable entrypoint at
#   /v1/data/<key>/main/compliance_report
# so a caller can evaluate any framework without knowing its package layout.
#
# If that path is undefined, or if any field inside the report object is
# undefined, OPA returns {} — the playbook stores a silently empty result
# instead of failing. These tests assert each bridge produces a populated,
# internally consistent report on EMPTY input, which is the case that
# previously collapsed to {}.

import rego.v1

# --- report is populated (not {} and not undefined) -------------------------

test_rhel9_report_populated if count(data.cis_rhel9.main.compliance_report) > 0

test_rhel8_report_populated if count(data.cis_rhel8.main.compliance_report) > 0

test_rocky8_report_populated if count(data.cis_rocky_linux_8.main.compliance_report) > 0

test_rocky9_report_populated if count(data.cis_rocky_linux_9.main.compliance_report) > 0

test_amazon2023_report_populated if count(data.cis_amazon_linux_2023.main.compliance_report) > 0

test_windows2022_report_populated if count(data.cis_windows_server_2022.main.compliance_report) > 0

test_windows2019_report_populated if count(data.cis_windows_server_2019.main.compliance_report) > 0

test_ubuntu2204_report_populated if count(data.cis_ubuntu_22_04.main.compliance_report) > 0

test_ubuntu2004_report_populated if count(data.cis_ubuntu_20_04.main.compliance_report) > 0

test_ubuntu2404_report_populated if count(data.cis_ubuntu_24_04.main.compliance_report) > 0

test_debian11_report_populated if count(data.cis_debian_11.main.compliance_report) > 0

test_vyos_report_populated if count(data.cis_vyos.main.compliance_report) > 0

test_pfsense_report_populated if count(data.cis_pfsense.main.compliance_report) > 0

test_opnsense_report_populated if count(data.cis_opnsense.main.compliance_report) > 0

test_gcp_report_populated if count(data.cis_gcp.main.compliance_report) > 0

test_eks_report_populated if count(data.cis_eks.main.compliance_report) > 0

test_suse16_report_populated if count(data.cis_suse16.main.compliance_report) > 0

test_ubuntu2604_report_populated if count(data.cis_ubuntu_26_04.main.compliance_report) > 0

test_sql_server_2025_report_populated if count(data.cis.sql_server_2025.main.compliance_report) > 0

test_sql_server_2022_report_populated if count(data.cis.sql_server_2022.main.compliance_report) > 0

test_intune_defender_av_report_populated if count(data.cis.intune_defender_antivirus.main.compliance_report) > 0

# --- counts are internally consistent and non-negative ----------------------

# Each report is read through `report_at(k)`, so that a test can evaluate a slice of the list (index modulo 4) instead of
# all of it: one test over all 27 reports took about five seconds on the oldest supported OPA. `reports` and
# `gated_reports` are built from `report_at`, so they are the same lists as before.
report_at(0) := data.cis_rhel9.main.compliance_report
report_at(1) := data.cis_rhel8.main.compliance_report
report_at(2) := data.cis_rocky_linux_8.main.compliance_report
report_at(3) := data.cis_rocky_linux_9.main.compliance_report
report_at(4) := data.cis_amazon_linux_2023.main.compliance_report
report_at(5) := data.cis_windows_server_2022.main.compliance_report
report_at(6) := data.cis_windows_server_2019.main.compliance_report
report_at(7) := data.cis_ubuntu_22_04.main.compliance_report
report_at(8) := data.cis_ubuntu_20_04.main.compliance_report
report_at(9) := data.cis_ubuntu_24_04.main.compliance_report
report_at(10) := data.cis_debian_11.main.compliance_report
report_at(11) := data.cis_vyos.main.compliance_report
report_at(12) := data.cis_pfsense.main.compliance_report
report_at(13) := data.cis_opnsense.main.compliance_report
report_at(14) := data.cis_gcp.main.compliance_report
report_at(15) := data.cis_eks.main.compliance_report
report_at(16) := data.cis_suse16.main.compliance_report
report_at(17) := data.cis_ubuntu_26_04.main.compliance_report
report_at(18) := data.cis.sql_server_2025.main.compliance_report
report_at(19) := data.cis.sql_server_2022.main.compliance_report
report_at(20) := data.cis.intune_defender_antivirus.main.compliance_report
report_at(21) := data.cis_postgresql.main.compliance_report
report_at(22) := data.cis_aws.main.compliance_report
report_at(23) := data.cis_azure.main.compliance_report
report_at(24) := data.cis_docker.main.compliance_report
report_at(25) := data.cis_kubernetes.main.compliance_report
report_at(26) := data.cis.rhel_10.main.compliance_report

reports := [report_at(k) | some k in numbers.range(0, 21)]

report_slice(i, ks) := [k | some j, k in ks; j % 4 == i]

test_the_report_slices_cover_every_report if {
	count(reports) == 22
	every i in numbers.range(0, 3) {
		every j, k in report_slice(i, numbers.range(0, 26)) {
			k == i + (j * 4)
		}
	}
	sum([count(report_slice(i, numbers.range(0, 26))) | some i in numbers.range(0, 3)]) == 27
}

test_no_negative_counts_slice_0 if {
	every r in [report_at(k) | some k in report_slice(0, numbers.range(0, 21))] {
		r.passed_controls >= 0
		r.failed_controls >= 0
		r.total_controls > 0
	}
}

test_no_negative_counts_slice_1 if {
	every r in [report_at(k) | some k in report_slice(1, numbers.range(0, 21))] {
		r.passed_controls >= 0
		r.failed_controls >= 0
		r.total_controls > 0
	}
}

test_no_negative_counts_slice_2 if {
	every r in [report_at(k) | some k in report_slice(2, numbers.range(0, 21))] {
		r.passed_controls >= 0
		r.failed_controls >= 0
		r.total_controls > 0
	}
}

test_no_negative_counts_slice_3 if {
	every r in [report_at(k) | some k in report_slice(3, numbers.range(0, 21))] {
		r.passed_controls >= 0
		r.failed_controls >= 0
		r.total_controls > 0
	}
}

test_percentage_in_range_slice_0 if {
	every r in [report_at(k) | some k in report_slice(0, numbers.range(0, 21))] {
		r.compliance_percentage >= 0
		r.compliance_percentage <= 100
	}
}

test_percentage_in_range_slice_1 if {
	every r in [report_at(k) | some k in report_slice(1, numbers.range(0, 21))] {
		r.compliance_percentage >= 0
		r.compliance_percentage <= 100
	}
}

test_percentage_in_range_slice_2 if {
	every r in [report_at(k) | some k in report_slice(2, numbers.range(0, 21))] {
		r.compliance_percentage >= 0
		r.compliance_percentage <= 100
	}
}

test_percentage_in_range_slice_3 if {
	every r in [report_at(k) | some k in report_slice(3, numbers.range(0, 21))] {
		r.compliance_percentage >= 0
		r.compliance_percentage <= 100
	}
}

test_required_fields_present_slice_0 if {
	every r in [report_at(k) | some k in report_slice(0, numbers.range(0, 21))] {
		is_string(r.framework)
		is_boolean(r.compliant)
		is_array(r.violations)
	}
}

test_required_fields_present_slice_1 if {
	every r in [report_at(k) | some k in report_slice(1, numbers.range(0, 21))] {
		is_string(r.framework)
		is_boolean(r.compliant)
		is_array(r.violations)
	}
}

test_required_fields_present_slice_2 if {
	every r in [report_at(k) | some k in report_slice(2, numbers.range(0, 21))] {
		is_string(r.framework)
		is_boolean(r.compliant)
		is_array(r.violations)
	}
}

test_required_fields_present_slice_3 if {
	every r in [report_at(k) | some k in report_slice(3, numbers.range(0, 21))] {
		is_string(r.framework)
		is_boolean(r.compliant)
		is_array(r.violations)
	}
}

# --- fail-closed: empty input must never report full compliance -------------
#
# Guards the cis_al2023 -> cis_amazon_linux_2023 import-prefix bug, where the
# orchestrator's imports pointed at a package that does not exist, so
# all_violations was always empty and the benchmark reported 100% on any input.

test_empty_input_is_not_compliant_slice_0 if {
	every r in [report_at(k) | some k in report_slice(0, numbers.range(0, 21))] { r.compliant == false }
}

test_empty_input_is_not_compliant_slice_1 if {
	every r in [report_at(k) | some k in report_slice(1, numbers.range(0, 21))] { r.compliant == false }
}

test_empty_input_is_not_compliant_slice_2 if {
	every r in [report_at(k) | some k in report_slice(2, numbers.range(0, 21))] { r.compliant == false }
}

test_empty_input_is_not_compliant_slice_3 if {
	every r in [report_at(k) | some k in report_slice(3, numbers.range(0, 21))] { r.compliant == false }
}

test_amazon2023_detects_violations_on_empty_input if {
	data.cis_amazon_linux_2023.main.compliance_report.failed_controls > 0
}

# --- derived policy sets must stay flagged -----------------------------------
#
# debian_11 contains a copy of another
# platform's controls (verified byte-identical by diff). They must never
# advertise a benchmark version they do not implement, and consumers must be
# able to detect the derivation programmatically.

derived_reports := [data.cis_debian_11.main.compliance_report]

test_derived_sets_are_flagged if {
	every r in derived_reports {
		r.derived == true
		is_string(r.derived_from)
		is_string(r.applied_to)
		startswith(r.benchmark, "DERIVED from ")
	}
}

test_derived_sets_do_not_claim_own_benchmark if {
	not contains(data.cis_debian_11.main.compliance_report.benchmark, "CIS Debian")
}

# ubuntu_24_04 is no longer derived: it is generated from the CIS Ubuntu 24.04 v2.0.1 workbook.
test_ubuntu2404_is_the_real_benchmark if {
	r := data.cis_ubuntu_24_04.main.compliance_report
	not "derived" in object.keys(r)
	r.benchmark == "CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.1"
}

# rocky_linux_9 was a derived set (a copy of rocky_linux_8) until it was rebuilt from the CIS Rocky Linux 9
# v3.0.0 workbook; it now names its own benchmark and carries no derivation flag.
test_rocky9_is_its_own_benchmark if {
	r := data.cis_rocky_linux_9.main.compliance_report
	r.benchmark == "CIS Rocky Linux 9 Benchmark v3.0.0"
	not "derived" in object.keys(r)
	r.standard_total == 352
}

# --- fail-closed on missing facts -------------------------------------------
#
# Most benchmarks phrase controls as "violate if the fact says X", so with NO
# facts nothing iterates and the benchmark reported near-total compliance for
# an assessment that evaluated nothing. Measured before the gate: cis_rhel10
# 99.0%, cis_azure 99.2%, cis_docker 99.1%, cis_kubernetes 99.2%, cis_aws
# 97.1%, cis_rhel9 71.9%. Two cis_rhel10 rows already in compliance_results
# carry exactly that empty-input signature.

gated_reports := array.concat(reports, [report_at(k) | some k in numbers.range(22, 26)])

test_empty_input_reports_zero_percent_slice_0 if {
	every r in [report_at(k) | some k in report_slice(0, numbers.range(0, 26))] { r.compliance_percentage == 0 }
}

test_empty_input_reports_zero_percent_slice_1 if {
	every r in [report_at(k) | some k in report_slice(1, numbers.range(0, 26))] { r.compliance_percentage == 0 }
}

test_empty_input_reports_zero_percent_slice_2 if {
	every r in [report_at(k) | some k in report_slice(2, numbers.range(0, 26))] { r.compliance_percentage == 0 }
}

test_empty_input_reports_zero_percent_slice_3 if {
	every r in [report_at(k) | some k in report_slice(3, numbers.range(0, 26))] { r.compliance_percentage == 0 }
}

test_empty_input_passes_no_controls_slice_0 if {
	every r in [report_at(k) | some k in report_slice(0, numbers.range(0, 26))] { r.passed_controls == 0 }
}

test_empty_input_passes_no_controls_slice_1 if {
	every r in [report_at(k) | some k in report_slice(1, numbers.range(0, 26))] { r.passed_controls == 0 }
}

test_empty_input_passes_no_controls_slice_2 if {
	every r in [report_at(k) | some k in report_slice(2, numbers.range(0, 26))] { r.passed_controls == 0 }
}

test_empty_input_passes_no_controls_slice_3 if {
	every r in [report_at(k) | some k in report_slice(3, numbers.range(0, 26))] { r.passed_controls == 0 }
}

test_empty_input_fails_every_control_slice_0 if {
	every r in [report_at(k) | some k in report_slice(0, numbers.range(0, 26))] { r.failed_controls == r.total_controls }
}

test_empty_input_fails_every_control_slice_1 if {
	every r in [report_at(k) | some k in report_slice(1, numbers.range(0, 26))] { r.failed_controls == r.total_controls }
}

test_empty_input_fails_every_control_slice_2 if {
	every r in [report_at(k) | some k in report_slice(2, numbers.range(0, 26))] { r.failed_controls == r.total_controls }
}

test_empty_input_fails_every_control_slice_3 if {
	every r in [report_at(k) | some k in report_slice(3, numbers.range(0, 26))] { r.failed_controls == r.total_controls }
}

test_empty_input_emits_explicit_fail_closed_violation_slice_0 if {
	every r in [report_at(k) | some k in report_slice(0, numbers.range(0, 26))] {
		some v in r.violations
		startswith(v, "FAIL-CLOSED: no facts supplied")
	}
}

test_empty_input_emits_explicit_fail_closed_violation_slice_1 if {
	every r in [report_at(k) | some k in report_slice(1, numbers.range(0, 26))] {
		some v in r.violations
		startswith(v, "FAIL-CLOSED: no facts supplied")
	}
}

test_empty_input_emits_explicit_fail_closed_violation_slice_2 if {
	every r in [report_at(k) | some k in report_slice(2, numbers.range(0, 26))] {
		some v in r.violations
		startswith(v, "FAIL-CLOSED: no facts supplied")
	}
}

test_empty_input_emits_explicit_fail_closed_violation_slice_3 if {
	every r in [report_at(k) | some k in report_slice(3, numbers.range(0, 26))] {
		some v in r.violations
		startswith(v, "FAIL-CLOSED: no facts supplied")
	}
}
