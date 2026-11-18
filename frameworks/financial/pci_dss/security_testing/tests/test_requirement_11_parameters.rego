package pci_dss.security_testing.requirement_11_test

import rego.v1

import data.pci_dss.security_testing.requirement_11 as r11

# Behaviour tests on the evidence schema (audit 2026-11-17, finding 4). Frequencies per PCI SSC's public
# SAQ D rows: 11.2.1 / 11.3.1 / 11.3.2 every three months, 11.4.2-11.4.3 every 12 months, 11.4.5 every
# 12 months (11.4.6 every six for service providers), 11.5.2 weekly, 11.6.1 weekly or per targeted risk
# analysis.

# --- 11.2 wireless -------------------------------------------------------------

_wireless(freq) := {"pci": {"wireless": {
	"authorized_access_points": {"inventoried": true},
	"rogue_detection": {"implemented": true, "frequency_days": freq},
	"unauthorized_access_points": {"alerts": {"configured": true}, "response": {"documented": true}},
}}}

test_11_2_1_quarterly_passes if r11.wireless_access_point_testing with input as _wireless(90)

test_11_2_1_four_months_fails if not r11.wireless_access_point_testing with input as _wireless(120)

test_11_2_1_string_frequency_fails if not r11.wireless_access_point_testing with input as _wireless("30")

test_11_2_1_missing_fails if not r11.wireless_access_point_testing with input as {"pci": {"wireless": {"rogue_detection": {"implemented": true}}}}

# --- 11.3.1 internal and 11.3.2 external scans ------------------------------------

_internal(freq) := {"pci": {"vuln_scanning": {"internal": {
	"performed": true, "frequency_days": freq, "qualified_personnel": true,
	"after_significant_changes": true, "high_and_critical": {"remediated": true}, "rescans": {"performed": true},
}}}}

test_11_3_1_quarterly_passes if r11.internal_vulnerability_scanning with input as _internal(90)

test_11_3_1_four_months_fails if not r11.internal_vulnerability_scanning with input as _internal(91)

test_11_3_1_frequency_missing_fails if {
	not r11.internal_vulnerability_scanning with input as {"pci": {"vuln_scanning": {"internal": {"performed": true}}}}
}

_external(freq) := {"pci": {"vuln_scanning": {"external": {
	"performed": true, "frequency_days": freq, "asv": {"approved": true},
	"passing_scan": {"achieved": true}, "after_significant_changes": true,
}}}}

test_11_3_2_quarterly_asv_passes if r11.external_vulnerability_scanning with input as _external(90)

test_11_3_2_four_months_fails if not r11.external_vulnerability_scanning with input as _external(100)

# --- 11.3.1 / 11.3.1.1 remediation --------------------------------------------------

_remediation(high) := {"pci": {"vuln_remediation": {
	"critical": {"resolved": true}, "high": high,
	"medium": {"risk_based_timeline": true}, "tracking": {"implemented": true},
	"verification": {"rescan_after_fix": true},
}}}

test_11_3_1_high_resolved_without_30_day_deadline_passes if {
	r11.vulnerability_remediation with input as _remediation({"resolved": true})
}

test_11_3_1_high_within_30_days_still_passes if {
	r11.vulnerability_remediation with input as _remediation({"within_30_days": true})
}

test_11_3_1_high_unresolved_fails if {
	not r11.vulnerability_remediation with input as _remediation({"resolved": false})
}

test_11_3_1_high_missing_fails if not r11.vulnerability_remediation with input as _remediation({})

# --- 11.4 penetration testing ---------------------------------------------------------

_pentest(freq) := {"pci": {"pen_testing": {
	"performed": true, "frequency_months": freq, "after_significant_infrastructure_changes": true,
	"qualified": {"independent_tester": true},
	"scope": {"network_layer": true, "application_layer": true, "includes_cde_perimeter": true, "includes_critical_systems": true},
}}}

test_11_4_annual_pentest_passes if r11.penetration_testing with input as _pentest(12)

test_11_4_thirteen_months_fails if not r11.penetration_testing with input as _pentest(13)

# --- 11.4.5 / 11.4.6 segmentation ---------------------------------------------------------

_seg(freq, entity) := {"pci": {
	"segmentation_testing": {
		"performed": true, "frequency_months": freq, "penetration_testing_method": true,
		"confirms_isolation": true, "after_segmentation_changes": true,
	},
	"entity": entity,
}}

test_11_4_5_merchant_annual_passes if r11.segmentation_testing with input as _seg(12, {"service_provider": false})

test_11_4_6_service_provider_annual_fails if not r11.segmentation_testing with input as _seg(12, {"service_provider": true})

test_11_4_6_service_provider_six_months_passes if r11.segmentation_testing with input as _seg(6, {"service_provider": true})

test_11_4_annual_with_entity_type_missing_fails if not r11.segmentation_testing with input as _seg(12, {})

test_11_4_5_merchant_thirteen_months_fails if not r11.segmentation_testing with input as _seg(13, {"service_provider": false})

test_11_4_5_segmentation_not_used_passes if {
	r11.segmentation_testing with input as {"pci": {"segmentation_testing": {"segmentation_used": false}}}
}

test_11_4_5_empty_input_fails if not r11.segmentation_testing with input as {}

# --- 11.5 IDS/IPS and change detection ------------------------------------------------------

_fim(freq) := {"pci": {"fim": {
	"deployed": true,
	"critical_files": {"covered": true}, "os_files": {"covered": true},
	"application_files": {"covered": true}, "configuration_files": {"covered": true},
	"alerts": {"immediate": true}, "comparison": {"against_baseline": true}, "frequency_days": freq,
}}}

test_11_5_2_weekly_passes if r11.file_integrity_monitoring with input as _fim(7)

test_11_5_2_eight_days_fails if not r11.file_integrity_monitoring with input as _fim(8)

test_11_5_1_ids_passes_without_real_time_flag if {
	r11.ids_ips_deployed with input as {"pci": {"ids_ips": {
		"deployed": true, "coverage": {"all_cde_network_traffic": true}, "signatures": {"current": true},
		"alerts": {"configured": true}, "personnel": {"responds_to_alerts": true},
	}}}
}

test_11_5_1_ids_not_deployed_fails if not r11.ids_ips_deployed with input as {"pci": {"ids_ips": {"deployed": false}}}

# --- 11.6.1 payment pages -------------------------------------------------------------------

_pages(detection) := {"pci": {"ecommerce": {"payment_pages": {
	"in_scope": true, "integrity_monitoring": true,
	"change_detection": object.union({"implemented": true}, detection),
	"script_inventory": {"maintained": true}, "alerts": {"configured": true},
}}}}

test_11_6_1_weekly_without_csp_passes if r11.payment_page_integrity with input as _pages({"frequency_days": 7})

test_11_6_1_targeted_risk_analysis_frequency_passes if {
	r11.payment_page_integrity with input as _pages({"frequency_days": 30, "tra_frequency_met": true})
}

test_11_6_1_monthly_without_tra_fails if not r11.payment_page_integrity with input as _pages({"frequency_days": 30})

test_11_6_1_frequency_missing_fails if not r11.payment_page_integrity with input as _pages({})

# --- roll-up on real evidence -------------------------------------------------------------------

test_empty_input_not_compliant_and_zero_score if {
	not r11.pci_requirement_11_compliant with input as {}
	r11.pci_requirement_11_score == 0 with input as {}
}
