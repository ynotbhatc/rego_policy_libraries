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

test_rhel9_report_populated if { count(data.cis_rhel9.main.compliance_report) > 0 }

test_rhel8_report_populated if { count(data.cis_rhel8.main.compliance_report) > 0 }

test_rocky8_report_populated if { count(data.cis_rocky_linux_8.main.compliance_report) > 0 }

test_rocky9_report_populated if { count(data.cis_rocky_linux_9.main.compliance_report) > 0 }

test_amazon2023_report_populated if { count(data.cis_amazon_linux_2023.main.compliance_report) > 0 }

test_windows2022_report_populated if { count(data.cis_windows_2022.main.compliance_report) > 0 }

test_windows2019_report_populated if { count(data.cis_windows_2019.main.compliance_report) > 0 }

test_ubuntu2204_report_populated if { count(data.cis_ubuntu_2204.main.compliance_report) > 0 }

test_ubuntu2004_report_populated if { count(data.cis_ubuntu_2004.main.compliance_report) > 0 }

test_ubuntu2404_report_populated if { count(data.cis_ubuntu_2404.main.compliance_report) > 0 }

test_debian11_report_populated if { count(data.cis_debian_11.main.compliance_report) > 0 }

test_vyos_report_populated if { count(data.cis_vyos.main.compliance_report) > 0 }

test_pfsense_report_populated if { count(data.cis_pfsense.main.compliance_report) > 0 }

test_gcp_report_populated if { count(data.cis_gcp.main.compliance_report) > 0 }

# --- counts are internally consistent and non-negative ----------------------

reports := [
	data.cis_rhel9.main.compliance_report,
	data.cis_rhel8.main.compliance_report,
	data.cis_rocky_linux_8.main.compliance_report,
	data.cis_rocky_linux_9.main.compliance_report,
	data.cis_amazon_linux_2023.main.compliance_report,
	data.cis_windows_2022.main.compliance_report,
	data.cis_windows_2019.main.compliance_report,
	data.cis_ubuntu_2204.main.compliance_report,
	data.cis_ubuntu_2004.main.compliance_report,
	data.cis_ubuntu_2404.main.compliance_report,
	data.cis_debian_11.main.compliance_report,
	data.cis_vyos.main.compliance_report,
	data.cis_pfsense.main.compliance_report,
	data.cis_gcp.main.compliance_report,
]

test_no_negative_counts if {
	every r in reports {
		r.passed_controls >= 0
		r.failed_controls >= 0
		r.total_controls > 0
	}
}

test_percentage_in_range if {
	every r in reports {
		r.compliance_percentage >= 0
		r.compliance_percentage <= 100
	}
}

test_required_fields_present if {
	every r in reports {
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

test_empty_input_is_not_compliant if {
	every r in reports { r.compliant == false }
}

test_amazon2023_detects_violations_on_empty_input if {
	data.cis_amazon_linux_2023.main.compliance_report.failed_controls > 0
}

# --- derived policy sets must stay flagged -----------------------------------
#
# debian_11, rocky_linux_9 and ubuntu_24_04 contain copies of another
# platform's controls (verified byte-identical by diff). They must never
# advertise a benchmark version they do not implement, and consumers must be
# able to detect the derivation programmatically.

derived_reports := [
	data.cis_debian_11.main.compliance_report,
	data.cis_rocky_linux_9.main.compliance_report,
	data.cis_ubuntu_2404.main.compliance_report,
]

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
	not contains(data.cis_rocky_linux_9.main.compliance_report.benchmark, "CIS Rocky Linux 9")
	not contains(data.cis_ubuntu_2404.main.compliance_report.benchmark, "CIS Ubuntu Linux 24.04")
}

# --- fail-closed on missing facts -------------------------------------------
#
# Most benchmarks phrase controls as "violate if the fact says X", so with NO
# facts nothing iterates and the benchmark reported near-total compliance for
# an assessment that evaluated nothing. Measured before the gate: cis_rhel10
# 99.0%, cis_azure 99.2%, cis_docker 99.1%, cis_kubernetes 99.2%, cis_aws
# 97.1%, cis_rhel9 71.9%. Two cis_rhel10 rows already in compliance_results
# carry exactly that empty-input signature.

gated_reports := array.concat(reports, [
	data.cis_aws.main.compliance_report,
	data.cis_azure.main.compliance_report,
	data.cis_docker.main.compliance_report,
	data.cis_kubernetes.main.compliance_report,
	data.cis_rhel10.main.compliance_report,
])

test_empty_input_reports_zero_percent if {
	every r in gated_reports { r.compliance_percentage == 0 }
}

test_empty_input_passes_no_controls if {
	every r in gated_reports { r.passed_controls == 0 }
}

test_empty_input_fails_every_control if {
	every r in gated_reports { r.failed_controls == r.total_controls }
}

test_empty_input_emits_explicit_fail_closed_violation if {
	every r in gated_reports {
		some v in r.violations
		startswith(v, "FAIL-CLOSED: no facts supplied")
	}
}
