package fedramp.main_test

import rego.v1
import data.fedramp.main

test_compliance_report_defined_on_empty_input if {
    r := main.compliance_report with input as {}
    r.framework == "FedRAMP"
    is_number(r.total_controls)
    is_array(r.violations)
}

test_non_compliant_on_empty_input if {
    not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
    count(main.violations) > 0 with input as {}
}

test_default_impact_level_is_moderate if {
    r := main.compliance_report with input as {}
    r.impact_level == "unknown"
    r.total_controls == 325
}

test_low_impact_drops_total_controls if {
    r := main.compliance_report with input as {"impact_level": "low"}
    r.impact_level == "low"
    r.total_controls == 125
}

test_high_impact_raises_total_controls if {
    r := main.compliance_report with input as {"impact_level": "high"}
    r.impact_level == "high"
    r.total_controls == 421
}
