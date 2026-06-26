package cfr_part_11.main_test

import rego.v1
import data.cfr_part_11.main

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
