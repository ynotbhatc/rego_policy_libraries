package nist.csf.main_test

import rego.v1

import data.nist.csf.main

# Smoke test — empty input should produce all violations and non-compliant.
test_empty_input_non_compliant if {
    not main.compliant with input as {}
}

test_empty_input_produces_violations if {
    count(main.violations) > 50 with input as {}
}

test_compliance_report_shape if {
    r := main.compliance_report with input as {}
    r.framework == "NIST Cybersecurity Framework 2.0"
    is_number(r.total_controls)
    is_array(r.violations)
    is_number(r.violation_count)
    r.compliant == false
}

test_function_summary_has_all_six_functions if {
    r := main.compliance_report with input as {}
    r.function_summary.govern
    r.function_summary.identify
    r.function_summary.protect
    r.function_summary.detect
    r.function_summary.respond
    r.function_summary.recover
}

# Partial-pass test — just the Recover function passes (only 6 controls).
recover_fully_compliant_input := {
    "recover": {
        "recovery_planning": {"recovery_plan_executed": true},
        "improvements": {"recovery_plans_incorporate_lessons": true, "recovery_strategies_updated": true},
        "communications": {
            "public_relations_managed": true,
            "reputation_repaired": true,
            "recovery_activities_communicated": true,
        },
    },
}

test_recover_function_passes_when_all_recover_inputs_true if {
    r := main.compliance_report with input as recover_fully_compliant_input
    r.function_summary.recover.compliant == true
}

test_other_functions_still_fail_when_only_recover_passes if {
    r := main.compliance_report with input as recover_fully_compliant_input
    r.function_summary.govern.compliant == false
    r.function_summary.identify.compliant == false
}
