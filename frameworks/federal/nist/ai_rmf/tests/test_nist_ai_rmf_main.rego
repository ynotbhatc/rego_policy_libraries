package nist_ai_rmf.main_test

import rego.v1
import data.nist_ai_rmf.main

test_compliance_report_defined_on_empty_input if {
    r := main.compliance_report with input as {}
    r.framework == "NIST AI Risk Management Framework (AI RMF)"
    r.version == "1.0"
    is_number(r.total_controls)
    is_array(r.violations)
}

test_non_compliant_on_empty_input if {
    not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
    count(main.violations) > 0 with input as {}
}

test_function_summary_present if {
    r := main.compliance_report with input as {}
    r.function_summary.GOVERN
    r.function_summary.MAP
    r.function_summary.MEASURE
    r.function_summary.MANAGE
    r.function_summary.TRUSTWORTHINESS
}

test_ai_system_name_from_input if {
    r := main.compliance_report with input as {
        "ai_system": {"name": "ResumeRanker"},
        "assessment_date": "2026-06-26",
    }
    r.ai_system == "ResumeRanker"
    r.assessed_at == "2026-06-26"
}
