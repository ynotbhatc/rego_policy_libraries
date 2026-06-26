package nis2.main_test

import rego.v1
import data.nis2.main

test_compliance_report_defined_on_empty_input if {
    r := main.compliance_report with input as {}
    r.framework == "EU Network and Information Security Directive 2 (NIS2)"
    is_number(r.total_controls)
    count(r.violations) >= 0
}

test_non_compliant_on_empty_input if {
    not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
    count(main.violations) > 20 with input as {}
}

test_defaults_for_metadata if {
    r := main.compliance_report with input as {}
    r.entity_name == "unknown"
    r.sector == "unknown"
    r.assessed_at == "unknown"
}

test_metadata_picked_up_from_input if {
    r := main.compliance_report with input as {
        "entity_name": "Big Bank Plc",
        "entity_type": "credit_institution",
        "sector": "banking",
        "entity_category": "essential",
        "assessment_date": "2026-06-26",
    }
    r.entity_name == "Big Bank Plc"
    r.sector == "banking"
    r.assessed_at == "2026-06-26"
}
