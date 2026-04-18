package technical_debt.scoring

import rego.v1

# =============================================================================
# AAC Technical Debt Scoring Policy
#
# Converts compliance violations into actionable debt items with effort
# estimates, business impact categorization, and priority scores.
#
# Input:
#   {
#     "hostname":      "web-prod-01",
#     "framework":     "cis_rhel9",
#     "violations":    ["CIS 1.1.1: ...", ...],
#     "debt_age_days": 0
#   }
#
# Output (POST /v1/data/technical_debt/scoring/debt_report):
#   { hostname, framework, total_violations, total_effort_hours,
#     debt_score, critical_count, high_count, by_category, items: [...] }
# =============================================================================

# ---------------------------------------------------------------------------
# Defaults — prevent undefined in report objects
# ---------------------------------------------------------------------------
default debt_score         := 0.0
default total_effort_hours := 0.0
default critical_count     := 0
default high_count         := 0

# ---------------------------------------------------------------------------
# Effort catalog
#
# effort_hours: median hours to remediate one violation of this type
# category:     security | compliance | operational
# complexity:   quick_win (<4h) | moderate (4-16h) | complex (>16h)
# severity:     CRITICAL | HIGH | MEDIUM | LOW
# ---------------------------------------------------------------------------
effort_catalog := {

    # ── CIS RHEL 9 ───────────────────────────────────────────────────────────
    # Keyed by "major.minor" section prefix extracted from "CIS X.Y.Z: ..."
    "cis_rhel9": {
        "1.1": {"hours": 0.5, "category": "operational",  "complexity": "quick_win", "severity": "MEDIUM"},
        "1.2": {"hours": 0.5, "category": "operational",  "complexity": "quick_win", "severity": "MEDIUM"},
        "1.3": {"hours": 1.0, "category": "operational",  "complexity": "quick_win", "severity": "MEDIUM"},
        "1.4": {"hours": 0.5, "category": "security",     "complexity": "quick_win", "severity": "HIGH"},
        "2.1": {"hours": 0.5, "category": "operational",  "complexity": "quick_win", "severity": "LOW"},
        "2.2": {"hours": 0.5, "category": "operational",  "complexity": "quick_win", "severity": "MEDIUM"},
        "2.3": {"hours": 0.5, "category": "operational",  "complexity": "quick_win", "severity": "MEDIUM"},
        "2.4": {"hours": 0.5, "category": "operational",  "complexity": "quick_win", "severity": "LOW"},
        "3.1": {"hours": 1.0, "category": "security",     "complexity": "quick_win", "severity": "HIGH"},
        "3.2": {"hours": 1.0, "category": "security",     "complexity": "quick_win", "severity": "HIGH"},
        "3.3": {"hours": 2.0, "category": "security",     "complexity": "quick_win", "severity": "HIGH"},
        "3.4": {"hours": 1.0, "category": "security",     "complexity": "quick_win", "severity": "MEDIUM"},
        "4.1": {"hours": 2.0, "category": "compliance",   "complexity": "quick_win", "severity": "HIGH"},
        "4.2": {"hours": 4.0, "category": "compliance",   "complexity": "moderate",  "severity": "HIGH"},
        "4.3": {"hours": 2.0, "category": "compliance",   "complexity": "quick_win", "severity": "MEDIUM"},
        "5.1": {"hours": 2.0, "category": "security",     "complexity": "quick_win", "severity": "HIGH"},
        "5.2": {"hours": 1.5, "category": "security",     "complexity": "quick_win", "severity": "HIGH"},
        "5.3": {"hours": 2.0, "category": "security",     "complexity": "quick_win", "severity": "HIGH"},
        "5.4": {"hours": 3.0, "category": "security",     "complexity": "moderate",  "severity": "CRITICAL"},
        "5.5": {"hours": 2.0, "category": "security",     "complexity": "quick_win", "severity": "HIGH"},
        "5.6": {"hours": 4.0, "category": "security",     "complexity": "moderate",  "severity": "CRITICAL"},
        "6.1": {"hours": 1.0, "category": "operational",  "complexity": "quick_win", "severity": "MEDIUM"},
        "6.2": {"hours": 0.5, "category": "operational",  "complexity": "quick_win", "severity": "LOW"},
        "_default": {"hours": 1.0, "category": "compliance", "complexity": "quick_win", "severity": "MEDIUM"}
    },

    # ── NERC CIP ─────────────────────────────────────────────────────────────
    # Keyed by standard ID "CIP-XXX" extracted from "CIP-007 R2: ..."
    "nerc_cip": {
        "CIP-002": {"hours": 16.0, "category": "compliance",  "complexity": "complex",  "severity": "CRITICAL"},
        "CIP-003": {"hours": 24.0, "category": "compliance",  "complexity": "complex",  "severity": "CRITICAL"},
        "CIP-004": {"hours": 8.0,  "category": "compliance",  "complexity": "moderate", "severity": "HIGH"},
        "CIP-005": {"hours": 24.0, "category": "security",    "complexity": "complex",  "severity": "CRITICAL"},
        "CIP-006": {"hours": 16.0, "category": "security",    "complexity": "complex",  "severity": "HIGH"},
        "CIP-007": {"hours": 16.0, "category": "security",    "complexity": "moderate", "severity": "HIGH"},
        "CIP-008": {"hours": 12.0, "category": "compliance",  "complexity": "moderate", "severity": "HIGH"},
        "CIP-009": {"hours": 8.0,  "category": "operational", "complexity": "moderate", "severity": "HIGH"},
        "CIP-010": {"hours": 12.0, "category": "operational", "complexity": "moderate", "severity": "HIGH"},
        "CIP-011": {"hours": 8.0,  "category": "security",    "complexity": "moderate", "severity": "HIGH"},
        "CIP-012": {"hours": 16.0, "category": "security",    "complexity": "complex",  "severity": "HIGH"},
        "CIP-013": {"hours": 16.0, "category": "compliance",  "complexity": "complex",  "severity": "HIGH"},
        "CIP-014": {"hours": 20.0, "category": "security",    "complexity": "complex",  "severity": "CRITICAL"},
        "CIP-015": {"hours": 20.0, "category": "security",    "complexity": "complex",  "severity": "HIGH"},
        "_default": {"hours": 12.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── NIST 800-53 ──────────────────────────────────────────────────────────
    # Keyed by control family prefix "AC", "AU", etc.
    "nist_800_53": {
        "AC": {"hours": 4.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "AU": {"hours": 3.0, "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "CA": {"hours": 8.0, "category": "compliance",  "complexity": "moderate",  "severity": "MEDIUM"},
        "CM": {"hours": 4.0, "category": "operational", "complexity": "moderate",  "severity": "MEDIUM"},
        "CP": {"hours": 8.0, "category": "operational", "complexity": "moderate",  "severity": "HIGH"},
        "IA": {"hours": 4.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "IR": {"hours": 8.0, "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "MA": {"hours": 4.0, "category": "operational", "complexity": "quick_win", "severity": "MEDIUM"},
        "MP": {"hours": 4.0, "category": "security",    "complexity": "quick_win", "severity": "MEDIUM"},
        "PE": {"hours": 8.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "PL": {"hours": 6.0, "category": "compliance",  "complexity": "moderate",  "severity": "MEDIUM"},
        "PS": {"hours": 4.0, "category": "compliance",  "complexity": "quick_win", "severity": "MEDIUM"},
        "RA": {"hours": 8.0, "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "SA": {"hours": 6.0, "category": "operational", "complexity": "moderate",  "severity": "MEDIUM"},
        "SC": {"hours": 6.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "SI": {"hours": 4.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "_default": {"hours": 4.0, "category": "compliance", "complexity": "moderate", "severity": "MEDIUM"}
    },

    # ── ISO 27001 ─────────────────────────────────────────────────────────────
    # Keyed by annex section "A.9", "A.10", etc.
    "iso27001": {
        "A.5":  {"hours": 8.0,  "category": "compliance",  "complexity": "moderate", "severity": "HIGH"},
        "A.6":  {"hours": 6.0,  "category": "compliance",  "complexity": "moderate", "severity": "MEDIUM"},
        "A.7":  {"hours": 8.0,  "category": "security",    "complexity": "moderate", "severity": "HIGH"},
        "A.8":  {"hours": 4.0,  "category": "security",    "complexity": "moderate", "severity": "HIGH"},
        "A.9":  {"hours": 6.0,  "category": "security",    "complexity": "moderate", "severity": "CRITICAL"},
        "A.10": {"hours": 8.0,  "category": "security",    "complexity": "complex",  "severity": "HIGH"},
        "A.11": {"hours": 12.0, "category": "security",    "complexity": "complex",  "severity": "HIGH"},
        "A.12": {"hours": 4.0,  "category": "operational", "complexity": "moderate", "severity": "HIGH"},
        "A.13": {"hours": 6.0,  "category": "security",    "complexity": "moderate", "severity": "HIGH"},
        "A.14": {"hours": 8.0,  "category": "operational", "complexity": "moderate", "severity": "HIGH"},
        "A.15": {"hours": 8.0,  "category": "compliance",  "complexity": "moderate", "severity": "HIGH"},
        "A.16": {"hours": 6.0,  "category": "compliance",  "complexity": "moderate", "severity": "HIGH"},
        "A.17": {"hours": 8.0,  "category": "operational", "complexity": "moderate", "severity": "HIGH"},
        "A.18": {"hours": 6.0,  "category": "compliance",  "complexity": "moderate", "severity": "HIGH"},
        "_default": {"hours": 6.0, "category": "compliance", "complexity": "moderate", "severity": "MEDIUM"}
    },

    # ── NCSC CAF ──────────────────────────────────────────────────────────────
    # Keyed by objective letter A-D
    "ncsc_caf": {
        "A": {"hours": 8.0, "category": "security",    "complexity": "moderate", "severity": "CRITICAL"},
        "B": {"hours": 6.0, "category": "security",    "complexity": "moderate", "severity": "HIGH"},
        "C": {"hours": 4.0, "category": "compliance",  "complexity": "moderate", "severity": "HIGH"},
        "D": {"hours": 6.0, "category": "operational", "complexity": "moderate", "severity": "HIGH"},
        "_default": {"hours": 6.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    }
}

# Global fallback used when framework is unknown
_global_default := {"hours": 2.0, "category": "compliance", "complexity": "moderate", "severity": "MEDIUM"}

# ---------------------------------------------------------------------------
# Framework-specific key extractors
# Each returns undefined if the violation string doesn't match the pattern.
# ---------------------------------------------------------------------------

# CIS RHEL 9: "CIS 5.2.1: ..." → "5.2"
_cis_key(violation) := key if {
    parts       := split(violation, " ")
    count(parts) >= 2
    parts[0]    == "CIS"
    ctrl_parts  := split(parts[1], ".")
    count(ctrl_parts) >= 2
    key         := concat(".", [ctrl_parts[0], ctrl_parts[1]])
}

# NERC CIP: "CIP-007 R2: ..." → "CIP-007"
_nerc_key(violation) := key if {
    parts      := split(violation, " ")
    count(parts) >= 1
    startswith(parts[0], "CIP-")
    # Strip any trailing requirement suffix (e.g. "CIP-007:" → "CIP-007")
    key        := trim_right(parts[0], ":")
}

# NIST 800-53: "AC-2: ..." → "AC"
_nist_key(violation) := key if {
    parts     := split(violation, "-")
    count(parts) >= 2
    family    := parts[0]
    # Family should be 2-3 uppercase letters
    regex.match(`^[A-Z]{2,3}$`, family)
    key       := family
}

# ISO 27001: "A.9.1.1: ..." → "A.9"
_iso_key(violation) := key if {
    startswith(violation, "A.")
    parts     := split(violation, ".")
    count(parts) >= 2
    # Handle two-digit section numbers (A.10, A.11 ...)
    key       := concat(".", [parts[0], parts[1]])
}

# NCSC CAF: "B2.a: ..." or "C1.b achieved/not_achieved" → "B"
_caf_key(violation) := key if {
    count(violation) >= 1
    first := substring(violation, 0, 1)
    regex.match(`^[A-D]$`, first)
    key   := first
}

# ---------------------------------------------------------------------------
# get_estimate — routes to framework-specific lookup, falls back gracefully.
# No mutual recursion: each clause is independent.
# ---------------------------------------------------------------------------

# CIS RHEL 9 — specific match
get_estimate("cis_rhel9", violation) := estimate if {
    key      := _cis_key(violation)
    estimate := effort_catalog.cis_rhel9[key]
}

# CIS RHEL 9 — default
get_estimate("cis_rhel9", violation) := effort_catalog.cis_rhel9["_default"] if {
    not _cis_key(violation)
}

get_estimate("cis_rhel9", violation) := effort_catalog.cis_rhel9["_default"] if {
    key := _cis_key(violation)
    not effort_catalog.cis_rhel9[key]
}

# NERC CIP — specific match
get_estimate("nerc_cip", violation) := estimate if {
    key      := _nerc_key(violation)
    estimate := effort_catalog.nerc_cip[key]
}

# NERC CIP — default
get_estimate("nerc_cip", violation) := effort_catalog.nerc_cip["_default"] if {
    not _nerc_key(violation)
}

get_estimate("nerc_cip", violation) := effort_catalog.nerc_cip["_default"] if {
    key := _nerc_key(violation)
    not effort_catalog.nerc_cip[key]
}

# NIST 800-53 — specific match
get_estimate("nist_800_53", violation) := estimate if {
    key      := _nist_key(violation)
    estimate := effort_catalog.nist_800_53[key]
}

# NIST 800-53 — default
get_estimate("nist_800_53", violation) := effort_catalog.nist_800_53["_default"] if {
    not _nist_key(violation)
}

get_estimate("nist_800_53", violation) := effort_catalog.nist_800_53["_default"] if {
    key := _nist_key(violation)
    not effort_catalog.nist_800_53[key]
}

# ISO 27001 — specific match
get_estimate("iso27001", violation) := estimate if {
    key      := _iso_key(violation)
    estimate := effort_catalog.iso27001[key]
}

# ISO 27001 — default
get_estimate("iso27001", violation) := effort_catalog.iso27001["_default"] if {
    not _iso_key(violation)
}

get_estimate("iso27001", violation) := effort_catalog.iso27001["_default"] if {
    key := _iso_key(violation)
    not effort_catalog.iso27001[key]
}

# NCSC CAF — specific match
get_estimate("ncsc_caf", violation) := estimate if {
    key      := _caf_key(violation)
    estimate := effort_catalog.ncsc_caf[key]
}

# NCSC CAF — default
get_estimate("ncsc_caf", violation) := effort_catalog.ncsc_caf["_default"] if {
    not _caf_key(violation)
}

get_estimate("ncsc_caf", violation) := effort_catalog.ncsc_caf["_default"] if {
    key := _caf_key(violation)
    not effort_catalog.ncsc_caf[key]
}

# Unknown framework — global fallback
get_estimate(framework, _violation) := _global_default if {
    not effort_catalog[framework]
}

# ---------------------------------------------------------------------------
# Severity → priority weight
# ---------------------------------------------------------------------------
_severity_weight := {"CRITICAL": 4.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5}

# ---------------------------------------------------------------------------
# Age multiplier — older unresolved debt scores higher
# ---------------------------------------------------------------------------
_age_mult(days) := 1.5  if { days >= 90 }
_age_mult(days) := 1.25 if { days >= 30; days < 90 }
_age_mult(days) := 1.0  if { days < 30 }

# ---------------------------------------------------------------------------
# Scored debt items — one per violation
# ---------------------------------------------------------------------------
debt_items contains item if {
    some violation in input.violations
    violation != ""
    estimate  := get_estimate(input.framework, violation)
    age       := object.get(input, "debt_age_days", 0)
    weight    := _severity_weight[estimate.severity]
    mult      := _age_mult(age)
    pscore    := weight * mult * (estimate.hours / 4.0)

    item := {
        "hostname":       input.hostname,
        "framework":      input.framework,
        "violation":      violation,
        "effort_hours":   estimate.hours,
        "debt_category":  estimate.category,
        "complexity":     estimate.complexity,
        "severity":       estimate.severity,
        "priority_score": pscore,
        "debt_age_days":  age
    }
}

# ---------------------------------------------------------------------------
# Aggregate totals
# ---------------------------------------------------------------------------
debt_score := score if {
    scores := [item.priority_score | some item in debt_items]
    count(scores) > 0
    score  := sum(scores)
}

total_effort_hours := hours if {
    all_hours := [item.effort_hours | some item in debt_items]
    count(all_hours) > 0
    hours := sum(all_hours)
}

critical_count := count([item | some item in debt_items; item.severity == "CRITICAL"])

high_count := count([item | some item in debt_items; item.severity == "HIGH"])

debt_by_category[cat] := totals if {
    some cat in {"security", "compliance", "operational"}
    cat_items := [item | some item in debt_items; item.debt_category == cat]
    totals := {
        "item_count":    count(cat_items),
        "effort_hours":  sum([i.effort_hours | some i in cat_items]),
        "priority_score": sum([i.priority_score | some i in cat_items])
    }
}

# ---------------------------------------------------------------------------
# Full debt report — top-level output returned to caller
# ---------------------------------------------------------------------------
default debt_report := {}

debt_report := report if {
    count(input.violations) > 0
    report := {
        "hostname":           input.hostname,
        "framework":          input.framework,
        "assessment_timestamp": time.now_ns(),
        "total_violations":   count(input.violations),
        "total_effort_hours": total_effort_hours,
        "debt_score":         debt_score,
        "critical_count":     critical_count,
        "high_count":         high_count,
        "by_category":        debt_by_category,
        "items":              [item | some item in debt_items]
    }
}
