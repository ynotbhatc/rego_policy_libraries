package cra.main_test

import rego.v1
import data.cra.main

# ── Empty-input smoke tests ────────────────────────────────────────────────

test_compliance_report_defined_on_empty_input if {
    r := main.compliance_report with input as {}
    r.framework == "EU Cyber Resilience Act (CRA)"
    r.regulation == "Regulation (EU) 2024/2847"
    r.total_controls == 88
    is_number(r.violation_count)
}

test_non_compliant_on_empty_input if {
    not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
    # All 6 modules should fire; expect close to total_controls.
    count(main.violations) > 50 with input as {}
}

test_module_summary_has_all_six_modules if {
    r := main.compliance_report with input as {}
    r.module_summary.essential_requirements
    r.module_summary.vulnerability_handling
    r.module_summary.incident_reporting
    r.module_summary.technical_documentation
    r.module_summary.conformity_assessment
    r.module_summary.manufacturer_obligations
}

test_defaults_for_metadata if {
    r := main.compliance_report with input as {}
    r.entity_name == "unknown"
    r.product_name == "unknown"
    r.product_class == "unknown"
    r.assessed_at == "unknown"
}

test_metadata_picked_up_from_input if {
    r := main.compliance_report with input as {
        "entity_name":     "Widget Maker GmbH",
        "product_name":    "ConnectedThermostat-7",
        "product_class":   "important_class_2",
        "assessment_date": "2026-06-26",
    }
    r.entity_name == "Widget Maker GmbH"
    r.product_class == "important_class_2"
    r.assessed_at == "2026-06-26"
}

# ── Targeted timeline-rule tests ────────────────────────────────────────────

# A vendor that is aware of an exploited vulnerability for >24h but hasn't
# sent early warning is in violation of Art.14(2)(a).
test_24h_early_warning_violation_when_late if {
    inp := {
        "incident_reporting": {
            "actively_exploited_vuln_known":   true,
            "hours_since_aware_of_vuln":       30,
            "early_warning_sent":              false,
        },
    }
    some v in main.violations with input as inp
    contains(v, "Art.14(2)(a)")
}

# A vendor that DID send the early warning within the window should not
# trigger Art.14(2)(a) (other rules may still fire).
test_24h_early_warning_clears_when_sent if {
    inp := {
        "incident_reporting": {
            "actively_exploited_vuln_known":   true,
            "hours_since_aware_of_vuln":       30,
            "early_warning_sent":              true,
        },
    }
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.14(2)(a)")]
    count(hits) == 0
}

# Important Class II product using Module A is non-conformant per Art.32(2).
test_module_a_insufficient_for_class_2 if {
    inp := {
        "conformity_assessment": {
            "product_class":    "important_class_2",
            "procedure_used":   "module_a",
        },
    }
    some v in main.violations with input as inp
    contains(v, "Art.32(2)")
}

# Support period below 5 years triggers Art.13(8) AND Annex II.2 rules
# (both essential vuln-handling + manufacturer modules check this).
test_short_support_period_triggers_both_rules if {
    inp := {
        "vulnerability_handling": {"support_period_years": 3},
        "manufacturer": {"support_period": {"declared": true, "years": 3}},
    }
    annex_hit := count([v | some v in main.violations with input as inp; contains(v, "Annex II.2")])
    art13_hit := count([v | some v in main.violations with input as inp; contains(v, "Art.13(8)")])
    annex_hit > 0
    art13_hit > 0
}
