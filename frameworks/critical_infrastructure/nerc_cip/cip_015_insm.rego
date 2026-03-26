package nerc_cip_cip015

import rego.v1

# NERC CIP-015: Internal Network Security Monitoring (INSM)
# FERC Approved: October 2024
# Effective: April 1, 2026 (High Impact w/ ERC); April 1, 2027 (Medium Impact w/ ERC)
#
# Applies to Responsible Entities with:
#   - High Impact BES Cyber Systems with External Routable Connectivity (ERC)
#   - Medium Impact BES Cyber Systems with External Routable Connectivity (ERC)
#
# Requirements:
#   R1 - Identify BES Cyber Systems requiring INSM; review annually
#   R2 - For each identified system: establish baseline, detect anomalies,
#         identify malicious comms, document response processes
#   R3 - Review and update INSM documentation within 15 calendar months

# ---------------------------------------------------------------------------
# R1: INSM Categorization
# Identify BES Cyber Systems with ERC that require INSM, review annually
# ---------------------------------------------------------------------------

r1_compliant if {
    r1_systems_identified
    r1_annual_review_current
}

# At least one system must be evaluated for INSM applicability
r1_systems_identified if {
    count(input.insm.systems) > 0
    every system in input.insm.systems {
        system.system_id
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        system.esp_name
    }
}

r1_annual_review_current if {
    review_ns := time.parse_rfc3339_ns(input.insm.categorization_review_date)
    age_days := (time.now_ns() - review_ns) / (24 * 60 * 60 * 1000000000)
    age_days <= 365
}

# ---------------------------------------------------------------------------
# R2: INSM Implementation
# For each system in R1, implement monitoring within each ESP
# ---------------------------------------------------------------------------

r2_compliant if {
    count(r2_violations) == 0
}

# R2.1: Network baseline established for each applicable system's ESP
r2_1_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.network_baseline.established == true
    ]
    count(violations) == 0
}

r2_1_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.network_baseline.documented == true
    ]
    count(violations) == 0
}

# R2.2: Anomaly detection implemented within each ESP
r2_2_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.anomaly_detection.implemented == true
    ]
    count(violations) == 0
}

r2_2_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.anomaly_detection.covers_esp == true
    ]
    count(violations) == 0
}

# R2.3: Capability to identify malicious communications within the ESP
r2_3_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.malicious_comm_detection.capability_documented == true
    ]
    count(violations) == 0
}

r2_3_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        count(system.malicious_comm_detection.tools) == 0
    ]
    count(violations) == 0
}

# R2.4: Response process for malicious or anomalous communications
r2_4_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.response_process.documented == true
    ]
    count(violations) == 0
}

r2_4_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.response_process.includes_notification == true
    ]
    count(violations) == 0
}

r2_4_compliant if {
    violations := [system |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.response_process.includes_investigation == true
    ]
    count(violations) == 0
}

# Aggregate R2 sub-requirement violations
r2_violations := violations if {
    r2_1_v := [v |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.network_baseline.established == true
        v := {
            "system_id": system.system_id,
            "sub_requirement": "R2.1",
            "finding": "Network baseline not established for ESP",
            "esp": system.esp_name
        }
    ]
    r2_2_v := [v |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.anomaly_detection.implemented == true
        v := {
            "system_id": system.system_id,
            "sub_requirement": "R2.2",
            "finding": "Anomaly detection not implemented within ESP",
            "esp": system.esp_name
        }
    ]
    r2_3_v := [v |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.malicious_comm_detection.capability_documented == true
        v := {
            "system_id": system.system_id,
            "sub_requirement": "R2.3",
            "finding": "Malicious communication detection capability not documented",
            "esp": system.esp_name
        }
    ]
    r2_4_v := [v |
        system := input.insm.systems[_]
        system.impact_categorization in ["high", "medium"]
        system.has_external_routable_connectivity == true
        not system.response_process.documented == true
        v := {
            "system_id": system.system_id,
            "sub_requirement": "R2.4",
            "finding": "Response process for anomalous/malicious communications not documented",
            "esp": system.esp_name
        }
    ]
    v_1_2 := array.concat(r2_1_v, r2_2_v)
    v_1_2_3 := array.concat(v_1_2, r2_3_v)
    violations := array.concat(v_1_2_3, r2_4_v)
}

# ---------------------------------------------------------------------------
# R3: Documentation Management
# Review and update INSM documentation within 15 calendar months (455 days)
# ---------------------------------------------------------------------------

r3_compliant if {
    r3_documentation_exists
    r3_review_current
}

r3_documentation_exists if {
    input.insm.documentation_review.documented == true
    input.insm.documentation_review.reviewer
}

r3_review_current if {
    review_ns := time.parse_rfc3339_ns(input.insm.documentation_review.last_review_date)
    age_days := (time.now_ns() - review_ns) / (24 * 60 * 60 * 1000000000)
    age_days <= 455
}

# ---------------------------------------------------------------------------
# Overall CIP-015 Compliance
# ---------------------------------------------------------------------------

default r1_compliant := false
default r2_compliant := false
default r3_compliant := false
default r2_1_compliant := false
default r2_2_compliant := false
default r2_3_compliant := false
default r2_4_compliant := false
default r3_documentation_exists := false
default r3_review_current := false
default r1_systems_identified := false
default r1_annual_review_current := false

cip_015_compliant if {
    r1_compliant
    r2_compliant
    r3_compliant
}

default cip_015_compliant := false

# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------

r1_violations := [violation |
    not r1_systems_identified
    violation := {
        "standard": "CIP-015",
        "requirement": "R1",
        "sub_requirement": "R1 - INSM Categorization",
        "severity": "high",
        "description": "BES Cyber Systems requiring INSM not properly identified or documented",
        "remediation": "Identify all High and Medium Impact BES Cyber Systems with External Routable Connectivity; document per R1 requirements"
    }
]

r1_review_violations := [violation |
    not r1_annual_review_current
    violation := {
        "standard": "CIP-015",
        "requirement": "R1",
        "sub_requirement": "R1 - Annual Review",
        "severity": "medium",
        "description": "INSM categorization review not performed within the last 365 days",
        "remediation": "Perform and document annual review of INSM categorization"
    }
]

r2_agg_violations := [violation |
    v := r2_violations[_]
    violation := {
        "standard": "CIP-015",
        "requirement": "R2",
        "sub_requirement": v.sub_requirement,
        "severity": "critical",
        "description": v.finding,
        "system_id": v.system_id,
        "esp": v.esp,
        "remediation": "Implement required INSM capability within the Electronic Security Perimeter"
    }
]

r3_violations := [violation |
    not r3_documentation_exists
    violation := {
        "standard": "CIP-015",
        "requirement": "R3",
        "sub_requirement": "R3 - Documentation",
        "severity": "medium",
        "description": "INSM documentation not established or missing required fields",
        "remediation": "Create and maintain INSM documentation with reviewer identification"
    }
]

r3_review_violations := [violation |
    not r3_review_current
    violation := {
        "standard": "CIP-015",
        "requirement": "R3",
        "sub_requirement": "R3 - Review Currency",
        "severity": "medium",
        "description": "INSM documentation not reviewed within 15 calendar months (455 days)",
        "remediation": "Review and update INSM documentation within the required 15-month window"
    }
]

cip_015_violations := violations if {
    v_r1 := array.concat(r1_violations, r1_review_violations)
    v_r1_r2 := array.concat(v_r1, r2_agg_violations)
    v_r1_r2_r3 := array.concat(v_r1_r2, r3_violations)
    violations := array.concat(v_r1_r2_r3, r3_review_violations)
}

# ---------------------------------------------------------------------------
# Compliance Score
# ---------------------------------------------------------------------------

default cip_015_score := 0

cip_015_score := score if {
    checks := [
        r1_systems_identified,
        r1_annual_review_current,
        r2_1_compliant,
        r2_2_compliant,
        r2_3_compliant,
        r2_4_compliant,
        r3_documentation_exists,
        r3_review_current
    ]
    passed := count([c | c := checks[_]; c == true])
    score := (passed * 100) / count(checks)
}

# ---------------------------------------------------------------------------
# Compliance Report
# ---------------------------------------------------------------------------

cip_015_compliance_report := {
    "standard": "CIP-015",
    "title": "Internal Network Security Monitoring (INSM)",
    "compliant": cip_015_compliant,
    "score": cip_015_score,
    "requirements": {
        "R1_insm_categorization": r1_compliant,
        "R2_insm_implementation": r2_compliant,
        "R3_documentation_management": r3_compliant
    },
    "sub_requirements": {
        "R2_1_network_baseline": r2_1_compliant,
        "R2_2_anomaly_detection": r2_2_compliant,
        "R2_3_malicious_comm_detection": r2_3_compliant,
        "R2_4_response_process": r2_4_compliant
    },
    "violations": cip_015_violations,
    "violation_count": count(cip_015_violations),
    "systems_assessed": count(input.insm.systems),
    "applicable_systems": count([s | s := input.insm.systems[_]; s.impact_categorization in ["high", "medium"]; s.has_external_routable_connectivity == true]),
    "metadata": {
        "standard": "NERC CIP-015",
        "full_title": "Internal Network Security Monitoring",
        "approved": "October 2024",
        "effective_high_impact": "April 1, 2026",
        "effective_medium_impact": "April 1, 2027",
        "regulatory_authority": "NERC / FERC",
        "penalties": "Up to $1M per day per violation"
    }
}
