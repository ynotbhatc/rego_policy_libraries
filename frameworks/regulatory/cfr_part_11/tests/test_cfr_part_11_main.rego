package cfr_part_11.main_test

import data.cfr_part_11.main
import rego.v1

test_compliance_report_defined_on_empty_input if {
	r := main.compliance_report with input as {}
	r.framework == "FDA 21 CFR Part 11"
	is_number(r.total_controls)
	count(r.violations) >= 0
}

test_non_compliant_on_empty_input if {
	not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
	count(main.violations) > 15 with input as {}
}

test_defaults_for_metadata if {
	r := main.compliance_report with input as {}
	r.entity_name == "unknown"
	r.system_name == "unknown"
}

test_metadata_picked_up_from_input if {
	r := main.compliance_report with input as {
		"entity_name": "PharmaCo",
		"entity_type": "pharmaceutical",
		"system_name": "Trial-Master",
		"assessment_date": "2026-06-26",
	}
	r.entity_name == "PharmaCo"
	r.system_name == "Trial-Master"
}

# Semantic review 2026-11-13: section buckets must not double-list 11.100/11.300 under 11.10/11.30.
test_section_summary_buckets_do_not_overlap if {
	r := data.cfr_part_11.main.compliance_report with input as {}
	count(r.section_summary.s11_10_closed_systems) == 22
	count(r.section_summary.s11_30_open_systems) == 2
	count(r.section_summary.s11_100_general_esig) == 3
	count(r.section_summary.s11_300_id_codes) == 5
}
