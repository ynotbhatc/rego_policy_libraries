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
#     "framework":     "cis_rhel9",          # or nerc_cip | ami | digital_sovereignty | ...
#     "violations":    ["CIS 1.1.1: ...", ...],  # may also be objects for digital_sovereignty
#     "debt_age_days": 0
#   }
#
# Output (POST /v1/data/technical_debt/scoring/debt_report):
#   { hostname, framework, total_violations, total_effort_hours,
#     debt_score, critical_count, high_count, by_category, items: [...] }
#
# Debt categories:
#   security               — generic security hygiene (CIS, NIST hardening, SWIFT CSP)
#   compliance             — regulatory & audit controls (ISO 27001, DORA, NIS2, NY DFS, SEC Cyber,
#                            HITRUST, 21 CFR Part 11, TISAX, NCSC CAF)
#   operational            — operational hygiene (patching, config drift)
#   critical_infrastructure — NERC-CIP, AMI 2.0 / NIST IR 7628, NIST 800-82 (OT/ICS)
#   sovereignty            — Digital Sovereignty controls (data residency, legal exposure, etc.)
#   technology_lifecycle   — EOL software, deprecated protocols, obsolete OT firmware
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
# category:     security | compliance | operational | critical_infrastructure | sovereignty
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
    # Category is critical_infrastructure — these are BES asset compliance items,
    # not generic security/compliance debt.
    "nerc_cip": {
        "CIP-002": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "CRITICAL"},
        "CIP-003": {"hours": 24.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "CRITICAL"},
        "CIP-004": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "CIP-005": {"hours": 24.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "CRITICAL"},
        "CIP-006": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "CIP-007": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "CIP-008": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "CIP-009": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "CIP-010": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "CIP-011": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "CIP-012": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "CIP-013": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "CIP-014": {"hours": 20.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "CRITICAL"},
        "CIP-015": {"hours": 20.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "_default": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"}
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
    },

    # ── AMI 2.0 / NIST IR 7628 ───────────────────────────────────────────────
    # Keyed by SG control family "SG.AC", "SG.CM", etc.
    # Violations are strings like "SG.AC-1: Access control policy..."
    # Category is critical_infrastructure — AMI systems are BES assets.
    "ami": {
        "SG.AC": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "CRITICAL"},
        "SG.AU": {"hours": 6.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "SG.CM": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "SG.IA": {"hours": 10.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "CRITICAL"},
        "SG.IR": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "SG.MA": {"hours": 6.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "MEDIUM"},
        "SG.MP": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "SG.PE": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "SG.PL": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "MEDIUM"},
        "SG.RA": {"hours": 10.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "SG.SA": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "SG.SC": {"hours": 10.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "CRITICAL"},
        "SG.SI": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "_default": {"hours": 8.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── Digital Sovereignty ───────────────────────────────────────────────────
    # Violations are OBJECTS from OPA: {control, domain, severity, description, remediation}
    # Keyed by domain prefix extracted from the "control" field:
    #   IS   — Infrastructure Sovereignty (cloud legal exposure, hardware supply chain)
    #   NS   — Network Sovereignty (DNS, CDN, BGP under foreign jurisdiction)
    #   SS   — Software Sovereignty (open-source dependency, vendor lock-in)
    #   OS   — Operational Sovereignty (support, key management, audit rights)
    #   CS   — Cryptographic Sovereignty (algorithm choice, key custody, FIPS)
    #   DR   — Data Residency (physical location, cross-border transfer)
    #   CR   — Cyber Resilience Sovereignty (incident response, recovery autonomy)
    #   GT   — Geopolitical Sovereignty (sanctions, export controls)
    #   AI   — AI/ML Sovereignty (model provenance, training data jurisdiction)
    #   BN   — Business Network Sovereignty (supply chain, third-party dependency)
    #   DORA — DORA operational resilience requirements (EU financial sector)
    # Category is sovereignty for all — this is a distinct dimension from security/compliance.
    "digital_sovereignty": {
        "IS":   {"hours": 24.0, "category": "sovereignty", "complexity": "complex",  "severity": "CRITICAL"},
        "NS":   {"hours": 16.0, "category": "sovereignty", "complexity": "complex",  "severity": "HIGH"},
        "SS":   {"hours": 20.0, "category": "sovereignty", "complexity": "complex",  "severity": "HIGH"},
        "OS":   {"hours": 12.0, "category": "sovereignty", "complexity": "moderate", "severity": "HIGH"},
        "CS":   {"hours": 16.0, "category": "sovereignty", "complexity": "complex",  "severity": "CRITICAL"},
        "DR":   {"hours": 20.0, "category": "sovereignty", "complexity": "complex",  "severity": "CRITICAL"},
        "CR":   {"hours": 12.0, "category": "sovereignty", "complexity": "moderate", "severity": "HIGH"},
        "GT":   {"hours": 8.0,  "category": "sovereignty", "complexity": "moderate", "severity": "HIGH"},
        "AI":   {"hours": 16.0, "category": "sovereignty", "complexity": "complex",  "severity": "HIGH"},
        "BN":   {"hours": 8.0,  "category": "sovereignty", "complexity": "moderate", "severity": "MEDIUM"},
        "DORA": {"hours": 24.0, "category": "sovereignty", "complexity": "complex",  "severity": "CRITICAL"},
        "_default": {"hours": 16.0, "category": "sovereignty", "complexity": "complex", "severity": "HIGH"}
    },

    # ── DORA (EU Digital Operational Resilience Act) ──────────────────────────
    # Violations: "DORA Art.5(1): ..." — key: article number "Art.5"
    "dora": {
        "Art.5":  {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "CRITICAL"},
        "Art.6":  {"hours": 12.0, "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "Art.8":  {"hours": 12.0, "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "Art.9":  {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "Art.10": {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "MEDIUM"},
        "Art.12": {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "CRITICAL"},
        "Art.13": {"hours": 12.0, "category": "compliance", "complexity": "complex",   "severity": "HIGH"},
        "Art.17": {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "CRITICAL"},
        "Art.18": {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "CRITICAL"},
        "Art.19": {"hours": 6.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "Art.25": {"hours": 20.0, "category": "compliance", "complexity": "complex",   "severity": "HIGH"},
        "Art.26": {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "HIGH"},
        "Art.28": {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "HIGH"},
        "Art.29": {"hours": 12.0, "category": "compliance", "complexity": "complex",   "severity": "HIGH"},
        "Art.30": {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "Art.45": {"hours": 4.0,  "category": "compliance", "complexity": "quick_win", "severity": "LOW"},
        "_default": {"hours": 12.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── NIS2 (EU Network and Information Security Directive 2) ────────────────
    # Violations: "NIS2 Art.21(2)(a): ..." — key: "Art.20", "Art.21", "Art.23"
    "nis2": {
        "Art.20": {"hours": 16.0, "category": "compliance", "complexity": "complex",  "severity": "CRITICAL"},
        "Art.21": {"hours": 12.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"},
        "Art.23": {"hours": 8.0,  "category": "compliance", "complexity": "moderate", "severity": "CRITICAL"},
        "_default": {"hours": 10.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── SEC Cybersecurity Disclosure Rules ────────────────────────────────────
    # Violations: "SEC Cyber Rule Item 1.05: ..." or "SEC Cyber Rule §229.106(b)(1): ..."
    # Key: "Item 1.05", "§229.106(b)", "§229.106(c)"
    "sec_cyber": {
        "Item 1.05":   {"hours": 8.0,  "category": "compliance", "complexity": "moderate", "severity": "CRITICAL"},
        "§229.106(b)": {"hours": 16.0, "category": "compliance", "complexity": "complex",  "severity": "HIGH"},
        "§229.106(c)": {"hours": 20.0, "category": "compliance", "complexity": "complex",  "severity": "HIGH"},
        "_default":    {"hours": 12.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── NY DFS 23 NYCRR Part 500 ──────────────────────────────────────────────
    # Violations: "23 NYCRR 500.4(a): ..." — key: "500.4"
    "ny_dfs": {
        "500.2":  {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "CRITICAL"},
        "500.3":  {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "500.4":  {"hours": 12.0, "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "500.5":  {"hours": 16.0, "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "500.6":  {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "500.7":  {"hours": 4.0,  "category": "security",   "complexity": "moderate",  "severity": "HIGH"},
        "500.9":  {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "HIGH"},
        "500.10": {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "MEDIUM"},
        "500.11": {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "500.12": {"hours": 4.0,  "category": "security",   "complexity": "quick_win", "severity": "CRITICAL"},
        "500.13": {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "MEDIUM"},
        "500.14": {"hours": 6.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "500.15": {"hours": 6.0,  "category": "security",   "complexity": "moderate",  "severity": "CRITICAL"},
        "500.16": {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "HIGH"},
        "500.17": {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "CRITICAL"},
        "_default": {"hours": 8.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── SWIFT CSP CSCF v2024 ──────────────────────────────────────────────────
    # Violations: "SWIFT CSP 1.1(M): ..." — key: "1.1"
    "swift_csp": {
        "1.1": {"hours": 16.0, "category": "security",    "complexity": "complex",   "severity": "CRITICAL"},
        "1.2": {"hours": 4.0,  "category": "security",    "complexity": "quick_win", "severity": "HIGH"},
        "1.3": {"hours": 8.0,  "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "1.4": {"hours": 8.0,  "category": "security",    "complexity": "moderate",  "severity": "CRITICAL"},
        "2.1": {"hours": 6.0,  "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "2.2": {"hours": 4.0,  "category": "operational", "complexity": "moderate",  "severity": "HIGH"},
        "2.3": {"hours": 6.0,  "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "2.4": {"hours": 6.0,  "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "2.5": {"hours": 8.0,  "category": "security",    "complexity": "moderate",  "severity": "CRITICAL"},
        "2.6": {"hours": 4.0,  "category": "security",    "complexity": "quick_win", "severity": "HIGH"},
        "2.7": {"hours": 4.0,  "category": "security",    "complexity": "quick_win", "severity": "HIGH"},
        "2.8": {"hours": 8.0,  "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "4.1": {"hours": 2.0,  "category": "security",    "complexity": "quick_win", "severity": "HIGH"},
        "5.1": {"hours": 4.0,  "category": "security",    "complexity": "moderate",  "severity": "CRITICAL"},
        "5.2": {"hours": 4.0,  "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "5.4": {"hours": 3.0,  "category": "security",    "complexity": "quick_win", "severity": "HIGH"},
        "6.1": {"hours": 2.0,  "category": "security",    "complexity": "quick_win", "severity": "HIGH"},
        "6.4": {"hours": 4.0,  "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "7.1": {"hours": 8.0,  "category": "compliance",  "complexity": "moderate",  "severity": "CRITICAL"},
        "7.2": {"hours": 3.0,  "category": "compliance",  "complexity": "quick_win", "severity": "MEDIUM"},
        "_default": {"hours": 6.0, "category": "security", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── NIST SP 800-82 Rev 3 (OT Security) ───────────────────────────────────
    # Violations: "NIST 800-82 RA-3(OT): ..." — key: NIST 800-53 family "RA", "SC", etc.
    # All OT controls → critical_infrastructure (OT specialist rates apply)
    "nist_800_82": {
        "RA": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "CRITICAL"},
        "CM": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "SC": {"hours": 20.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "CRITICAL"},
        "AC": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "AU": {"hours": 6.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "SI": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "IR": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "CP": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "MA": {"hours": 8.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "MEDIUM"},
        "MP": {"hours": 6.0,  "category": "critical_infrastructure", "complexity": "moderate", "severity": "MEDIUM"},
        "PE": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"},
        "SA": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "SR": {"hours": 16.0, "category": "critical_infrastructure", "complexity": "complex",  "severity": "HIGH"},
        "_default": {"hours": 12.0, "category": "critical_infrastructure", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── HITRUST CSF v11.3.0 ───────────────────────────────────────────────────
    # Violations: "HITRUST CSF 01.a: ..." — key: 2-digit category "00"–"18"
    "hitrust": {
        "00": {"hours": 16.0, "category": "compliance",  "complexity": "complex",   "severity": "CRITICAL"},
        "01": {"hours": 4.0,  "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "02": {"hours": 4.0,  "category": "compliance",  "complexity": "quick_win", "severity": "MEDIUM"},
        "03": {"hours": 12.0, "category": "compliance",  "complexity": "moderate",  "severity": "CRITICAL"},
        "04": {"hours": 8.0,  "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "06": {"hours": 8.0,  "category": "compliance",  "complexity": "moderate",  "severity": "CRITICAL"},
        "07": {"hours": 4.0,  "category": "compliance",  "complexity": "quick_win", "severity": "MEDIUM"},
        "08": {"hours": 8.0,  "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "09": {"hours": 6.0,  "category": "operational", "complexity": "moderate",  "severity": "HIGH"},
        "10": {"hours": 12.0, "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "11": {"hours": 4.0,  "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "12": {"hours": 6.0,  "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "13": {"hours": 4.0,  "category": "compliance",  "complexity": "quick_win", "severity": "MEDIUM"},
        "14": {"hours": 8.0,  "category": "compliance",  "complexity": "moderate",  "severity": "CRITICAL"},
        "15": {"hours": 12.0, "category": "compliance",  "complexity": "moderate",  "severity": "CRITICAL"},
        "16": {"hours": 8.0,  "category": "operational", "complexity": "moderate",  "severity": "HIGH"},
        "17": {"hours": 8.0,  "category": "security",    "complexity": "moderate",  "severity": "CRITICAL"},
        "18": {"hours": 8.0,  "category": "compliance",  "complexity": "moderate",  "severity": "HIGH"},
        "_default": {"hours": 8.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── 21 CFR Part 11 (FDA Electronic Records) ───────────────────────────────
    # Violations: "21 CFR 11.10(a): ..." — key: "11.10", "11.30", etc.
    "cfr_part_11": {
        "11.10":  {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "CRITICAL"},
        "11.30":  {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "11.50":  {"hours": 6.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "11.70":  {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "CRITICAL"},
        "11.100": {"hours": 4.0,  "category": "compliance", "complexity": "quick_win", "severity": "HIGH"},
        "11.200": {"hours": 6.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "11.300": {"hours": 4.0,  "category": "compliance", "complexity": "quick_win", "severity": "HIGH"},
        "_default": {"hours": 8.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── TISAX VDA ISA v6.0.3 ─────────────────────────────────────────────────
    # Violations: "TISAX VDA ISA 1.1.1: ..." → key "1"; "TISAX PD AL2: ..." → key "PD"
    "tisax": {
        "1":  {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "CRITICAL"},
        "2":  {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "3":  {"hours": 4.0,  "category": "compliance", "complexity": "moderate",  "severity": "MEDIUM"},
        "4":  {"hours": 8.0,  "category": "security",   "complexity": "moderate",  "severity": "HIGH"},
        "5":  {"hours": 8.0,  "category": "security",   "complexity": "moderate",  "severity": "HIGH"},
        "6":  {"hours": 4.0,  "category": "security",   "complexity": "moderate",  "severity": "HIGH"},
        "7":  {"hours": 12.0, "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "8":  {"hours": 8.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "9":  {"hours": 6.0,  "category": "compliance", "complexity": "moderate",  "severity": "HIGH"},
        "PD": {"hours": 16.0, "category": "compliance", "complexity": "complex",   "severity": "CRITICAL"},
        "_default": {"hours": 8.0, "category": "compliance", "complexity": "moderate", "severity": "HIGH"}
    },

    # ── CIS GCP Foundation Benchmark v2.0.0 ──────────────────────────────────
    # Violations: "CIS GCP 1.1: ..." — key: section number "1"–"8"
    "cis_gcp": {
        "1": {"hours": 4.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "2": {"hours": 2.0, "category": "compliance",  "complexity": "quick_win", "severity": "MEDIUM"},
        "3": {"hours": 4.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "4": {"hours": 2.0, "category": "security",    "complexity": "quick_win", "severity": "HIGH"},
        "5": {"hours": 2.0, "category": "security",    "complexity": "quick_win", "severity": "HIGH"},
        "6": {"hours": 4.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "7": {"hours": 4.0, "category": "security",    "complexity": "moderate",  "severity": "HIGH"},
        "8": {"hours": 6.0, "category": "operational", "complexity": "moderate",  "severity": "HIGH"},
        "_default": {"hours": 4.0, "category": "security", "complexity": "moderate", "severity": "HIGH"}
    }
}

# Global fallback used when framework is unknown
_global_default := {"hours": 2.0, "category": "compliance", "complexity": "moderate", "severity": "MEDIUM"}

# ---------------------------------------------------------------------------
# Violation normalizer
#
# Handles multiple violation shapes from different compliance playbooks:
#   1. Plain string:    "CIS 5.2.1: Ensure SSH root login is disabled"
#   2. DS object:       {control: "IS-001", description: "...", domain: "..."}
#   3. CIS DB object:   {control_id: "1.1.2.1", severity: "medium", description: "..."}
#
# _violation_as_string normalises all forms to a string for storage + key extraction.
# ---------------------------------------------------------------------------

_violation_as_string(v) := v if { is_string(v) }

# Object with "control" field (Digital Sovereignty and similar)
_violation_as_string(v) := s if {
    not is_string(v)
    v.control
    v.description
    s := sprintf("%s: %s", [v.control, v.description])
}

_violation_as_string(v) := s if {
    not is_string(v)
    v.control
    not v.description
    s := v.control
}

# Object with "control_id" field (CIS DB schema — {control_id, severity, description})
_violation_as_string(v) := s if {
    not is_string(v)
    not v.control
    v.control_id
    v.description
    s := sprintf("%s: %s", [v.control_id, v.description])
}

_violation_as_string(v) := s if {
    not is_string(v)
    not v.control
    v.control_id
    not v.description
    s := v.control_id
}

# ---------------------------------------------------------------------------
# Framework-specific key extractors
# Each returns undefined if the violation string doesn't match the pattern.
# ---------------------------------------------------------------------------

# CIS RHEL 9: "CIS 5.2.1: ..." → "5.2"
_cis_key(violation) := key if {
    is_string(violation)
    parts       := split(violation, " ")
    count(parts) >= 2
    parts[0]    == "CIS"
    ctrl_parts  := split(parts[1], ".")
    count(ctrl_parts) >= 2
    key         := concat(".", [ctrl_parts[0], ctrl_parts[1]])
}

# CIS RHEL 9 object: {control_id: "1.1.2.1", ...} → "1.1"
_cis_key(violation) := key if {
    not is_string(violation)
    violation.control_id
    ctrl_parts  := split(violation.control_id, ".")
    count(ctrl_parts) >= 2
    key         := concat(".", [ctrl_parts[0], ctrl_parts[1]])
}

# NERC CIP: "CIP-007 R2: ..." → "CIP-007"
_nerc_key(violation) := key if {
    is_string(violation)
    parts      := split(violation, " ")
    count(parts) >= 1
    startswith(parts[0], "CIP-")
    key        := trim_right(parts[0], ":")
}

# NIST 800-53: "AC-2: ..." → "AC"
_nist_key(violation) := key if {
    is_string(violation)
    parts     := split(violation, "-")
    count(parts) >= 2
    family    := parts[0]
    regex.match(`^[A-Z]{2,3}$`, family)
    key       := family
}

# ISO 27001: "A.9.1.1: ..." → "A.9"
_iso_key(violation) := key if {
    is_string(violation)
    startswith(violation, "A.")
    parts     := split(violation, ".")
    count(parts) >= 2
    key       := concat(".", [parts[0], parts[1]])
}

# NCSC CAF: "B2.a: ..." or "C1.b achieved/not_achieved" → "B"
_caf_key(violation) := key if {
    is_string(violation)
    count(violation) >= 1
    first := substring(violation, 0, 1)
    regex.match(`^[A-D]$`, first)
    key   := first
}

# AMI / NIST IR 7628: "SG.AC-1: ..." → "SG.AC"
_ami_key(violation) := key if {
    is_string(violation)
    startswith(violation, "SG.")
    # Remove "SG." prefix, split on "-", take first part = control family
    rest          := substring(violation, 3, count(violation))
    family_parts  := split(rest, "-")
    count(family_parts) >= 1
    key           := concat(".", ["SG", family_parts[0]])
}

# Digital Sovereignty: object with "control" field "IS-001" → "IS", "DORA-001" → "DORA"
_ds_key(violation) := key if {
    not is_string(violation)
    violation.control
    ctrl_parts := split(violation.control, "-")
    count(ctrl_parts) >= 2
    key        := ctrl_parts[0]
}

# DORA: "DORA Art.5(1): ..." → "Art.5"
_dora_key(violation) := key if {
    is_string(violation)
    startswith(violation, "DORA ")
    parts := split(violation, " ")
    count(parts) >= 2
    art_raw := parts[1]                          # "Art.5(1):" or "Art.17:"
    key     := split(split(art_raw, "(")[0], ":")[0]  # "Art.5" or "Art.17"
}

# NIS2: "NIS2 Art.21(2)(a): ..." → "Art.21"; "NIS2 Art.20: ..." → "Art.20"
_nis2_key(violation) := key if {
    is_string(violation)
    startswith(violation, "NIS2 ")
    parts := split(violation, " ")
    count(parts) >= 2
    art_raw := parts[1]                          # "Art.21(2)(a):" or "Art.20:"
    key     := split(split(art_raw, "(")[0], ":")[0]
}

# SEC Cyber: "SEC Cyber Rule Item 1.05: ..." → "Item 1.05"
_sec_key(violation) := "Item 1.05" if {
    is_string(violation)
    contains(violation, "Item 1.05")
}

# SEC Cyber: "SEC Cyber Rule §229.106(c)(1): ..." → "§229.106(c)"
_sec_key(violation) := "§229.106(c)" if {
    is_string(violation)
    contains(violation, "§229.106(c)")
}

# SEC Cyber: "SEC Cyber Rule §229.106(b)(1): ..." → "§229.106(b)"
_sec_key(violation) := "§229.106(b)" if {
    is_string(violation)
    contains(violation, "§229.106(b)")
    not contains(violation, "§229.106(c)")
}

# NY DFS: "23 NYCRR 500.4(a): ..." → "500.4"
_nydfs_key(violation) := key if {
    is_string(violation)
    startswith(violation, "23 NYCRR ")
    parts := split(violation, " ")
    count(parts) >= 3
    sect_raw := parts[2]                         # "500.4(a):" or "500.12:"
    key      := split(split(sect_raw, "(")[0], ":")[0]
}

# SWIFT CSP: "SWIFT CSP 1.1(M): ..." → "1.1"
_swift_key(violation) := key if {
    is_string(violation)
    startswith(violation, "SWIFT CSP ")
    parts := split(violation, " ")
    count(parts) >= 3
    ctrl_raw := parts[2]                         # "1.1(M):" or "6.4(M):"
    key      := split(split(ctrl_raw, "(")[0], ":")[0]
}

# NIST 800-82 (OT): "NIST 800-82 RA-3(OT): ..." → "RA"
_nist_ot_key(violation) := key if {
    is_string(violation)
    startswith(violation, "NIST 800-82 ")
    rest  := substring(violation, 12, count(violation))  # "RA-3(OT): ..."
    parts := split(rest, "-")
    count(parts) >= 2
    key   := parts[0]
}

# HITRUST: "HITRUST CSF 01.a: ..." → "01"
_hitrust_key(violation) := key if {
    is_string(violation)
    startswith(violation, "HITRUST CSF ")
    parts := split(violation, " ")
    count(parts) >= 3
    ctrl_raw := parts[2]                         # "01.a:" or "14.a:"
    key      := split(split(ctrl_raw, ".")[0], ":")[0]
}

# 21 CFR Part 11: "21 CFR 11.10(a): ..." → "11.10"
_cfr11_key(violation) := key if {
    is_string(violation)
    startswith(violation, "21 CFR ")
    parts := split(violation, " ")
    count(parts) >= 3
    ctrl_raw := parts[2]                         # "11.10(a):" or "11.100(c):"
    key      := split(split(ctrl_raw, "(")[0], ":")[0]
}

# TISAX: "TISAX VDA ISA 1.1.1: ..." → "1"; "TISAX PD AL2: ..." → "PD"
_tisax_key(violation) := key if {
    is_string(violation)
    startswith(violation, "TISAX VDA ISA ")
    parts := split(violation, " ")
    count(parts) >= 4
    ctrl_raw := parts[3]                         # "1.1.1:" or "9.2.1:"
    key      := split(split(ctrl_raw, ".")[0], ":")[0]
}

_tisax_key(violation) := "PD" if {
    is_string(violation)
    startswith(violation, "TISAX PD ")
}

# CIS GCP: "CIS GCP 1.1: ..." → "1"
_cis_gcp_key(violation) := key if {
    is_string(violation)
    startswith(violation, "CIS GCP ")
    parts := split(violation, " ")
    count(parts) >= 3
    ctrl_raw := parts[2]                         # "1.1:" or "8.9:"
    key      := split(split(ctrl_raw, ".")[0], ":")[0]
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

# AMI / NIST IR 7628 — specific match
get_estimate("ami", violation) := estimate if {
    key      := _ami_key(violation)
    estimate := effort_catalog.ami[key]
}

# AMI — default
get_estimate("ami", violation) := effort_catalog.ami["_default"] if {
    not _ami_key(violation)
}

get_estimate("ami", violation) := effort_catalog.ami["_default"] if {
    key := _ami_key(violation)
    not effort_catalog.ami[key]
}

# Digital Sovereignty — specific match (object violations)
get_estimate("digital_sovereignty", violation) := estimate if {
    key      := _ds_key(violation)
    estimate := effort_catalog.digital_sovereignty[key]
}

# Digital Sovereignty — default (key not in catalog)
get_estimate("digital_sovereignty", violation) := effort_catalog.digital_sovereignty["_default"] if {
    not _ds_key(violation)
}

get_estimate("digital_sovereignty", violation) := effort_catalog.digital_sovereignty["_default"] if {
    key := _ds_key(violation)
    not effort_catalog.digital_sovereignty[key]
}

# DORA — specific match
get_estimate("dora", violation) := estimate if {
    key      := _dora_key(violation)
    estimate := effort_catalog.dora[key]
}

get_estimate("dora", violation) := effort_catalog.dora["_default"] if {
    not _dora_key(violation)
}

get_estimate("dora", violation) := effort_catalog.dora["_default"] if {
    key := _dora_key(violation)
    not effort_catalog.dora[key]
}

# NIS2 — specific match
get_estimate("nis2", violation) := estimate if {
    key      := _nis2_key(violation)
    estimate := effort_catalog.nis2[key]
}

get_estimate("nis2", violation) := effort_catalog.nis2["_default"] if {
    not _nis2_key(violation)
}

get_estimate("nis2", violation) := effort_catalog.nis2["_default"] if {
    key := _nis2_key(violation)
    not effort_catalog.nis2[key]
}

# SEC Cyber — specific match
get_estimate("sec_cyber", violation) := estimate if {
    key      := _sec_key(violation)
    estimate := effort_catalog.sec_cyber[key]
}

get_estimate("sec_cyber", violation) := effort_catalog.sec_cyber["_default"] if {
    not _sec_key(violation)
}

get_estimate("sec_cyber", violation) := effort_catalog.sec_cyber["_default"] if {
    key := _sec_key(violation)
    not effort_catalog.sec_cyber[key]
}

# NY DFS — specific match
get_estimate("ny_dfs", violation) := estimate if {
    key      := _nydfs_key(violation)
    estimate := effort_catalog.ny_dfs[key]
}

get_estimate("ny_dfs", violation) := effort_catalog.ny_dfs["_default"] if {
    not _nydfs_key(violation)
}

get_estimate("ny_dfs", violation) := effort_catalog.ny_dfs["_default"] if {
    key := _nydfs_key(violation)
    not effort_catalog.ny_dfs[key]
}

# SWIFT CSP — specific match
get_estimate("swift_csp", violation) := estimate if {
    key      := _swift_key(violation)
    estimate := effort_catalog.swift_csp[key]
}

get_estimate("swift_csp", violation) := effort_catalog.swift_csp["_default"] if {
    not _swift_key(violation)
}

get_estimate("swift_csp", violation) := effort_catalog.swift_csp["_default"] if {
    key := _swift_key(violation)
    not effort_catalog.swift_csp[key]
}

# NIST 800-82 (OT) — specific match
get_estimate("nist_800_82", violation) := estimate if {
    key      := _nist_ot_key(violation)
    estimate := effort_catalog.nist_800_82[key]
}

get_estimate("nist_800_82", violation) := effort_catalog.nist_800_82["_default"] if {
    not _nist_ot_key(violation)
}

get_estimate("nist_800_82", violation) := effort_catalog.nist_800_82["_default"] if {
    key := _nist_ot_key(violation)
    not effort_catalog.nist_800_82[key]
}

# HITRUST — specific match
get_estimate("hitrust", violation) := estimate if {
    key      := _hitrust_key(violation)
    estimate := effort_catalog.hitrust[key]
}

get_estimate("hitrust", violation) := effort_catalog.hitrust["_default"] if {
    not _hitrust_key(violation)
}

get_estimate("hitrust", violation) := effort_catalog.hitrust["_default"] if {
    key := _hitrust_key(violation)
    not effort_catalog.hitrust[key]
}

# 21 CFR Part 11 — specific match
get_estimate("cfr_part_11", violation) := estimate if {
    key      := _cfr11_key(violation)
    estimate := effort_catalog.cfr_part_11[key]
}

get_estimate("cfr_part_11", violation) := effort_catalog.cfr_part_11["_default"] if {
    not _cfr11_key(violation)
}

get_estimate("cfr_part_11", violation) := effort_catalog.cfr_part_11["_default"] if {
    key := _cfr11_key(violation)
    not effort_catalog.cfr_part_11[key]
}

# TISAX — specific match
get_estimate("tisax", violation) := estimate if {
    key      := _tisax_key(violation)
    estimate := effort_catalog.tisax[key]
}

get_estimate("tisax", violation) := effort_catalog.tisax["_default"] if {
    not _tisax_key(violation)
}

get_estimate("tisax", violation) := effort_catalog.tisax["_default"] if {
    key := _tisax_key(violation)
    not effort_catalog.tisax[key]
}

# CIS GCP — specific match
get_estimate("cis_gcp", violation) := estimate if {
    key      := _cis_gcp_key(violation)
    estimate := effort_catalog.cis_gcp[key]
}

get_estimate("cis_gcp", violation) := effort_catalog.cis_gcp["_default"] if {
    not _cis_gcp_key(violation)
}

get_estimate("cis_gcp", violation) := effort_catalog.cis_gcp["_default"] if {
    key := _cis_gcp_key(violation)
    not effort_catalog.cis_gcp[key]
}

# Unknown framework — global fallback
get_estimate(framework, _violation) := _global_default if {
    not effort_catalog[framework]
}

# ---------------------------------------------------------------------------
# Severity → priority weight
# ---------------------------------------------------------------------------
_severity_weight := {"CRITICAL": 4.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5}

# Normalise severity from object violations (lowercase) to uppercase
_norm_severity(s) := upper(s)

# ---------------------------------------------------------------------------
# Age multiplier — older unresolved debt scores higher
# ---------------------------------------------------------------------------
_age_mult(days) := 1.5  if { days >= 90 }
_age_mult(days) := 1.25 if { days >= 30; days < 90 }
_age_mult(days) := 1.0  if { days < 30 }

# ---------------------------------------------------------------------------
# Violation severity extractor
#
# object.get() requires its first argument to be an object (OPA type-checks
# at runtime and returns undefined — not the default — when given a string).
# Use explicit Rego clauses instead so string violations fall through to the
# catalog default and object violations use their own severity field.
# ---------------------------------------------------------------------------

# Object violation with severity field (DS, CIS-DB-schema objects)
_violation_sev(violation, _default) := violation.severity if {
    not is_string(violation)
    violation.severity
}

# String violation → use catalog default
_violation_sev(violation, _default) := _default if {
    is_string(violation)
}

# Object violation without severity field → use catalog default
_violation_sev(violation, _default) := _default if {
    not is_string(violation)
    not violation.severity
}

# ---------------------------------------------------------------------------
# Scored debt items — one per violation
# Handles both string violations (all frameworks) and object violations (DS).
# ---------------------------------------------------------------------------
debt_items contains item if {
    some violation in input.violations
    violation_str := _violation_as_string(violation)
    violation_str != ""
    estimate      := get_estimate(input.framework, violation)
    age           := object.get(input, "debt_age_days", 0)

    # For object violations (DS), use the object's own severity if present.
    # For string violations, use the catalog severity.
    raw_sev  := _violation_sev(violation, estimate.severity)
    severity := _norm_severity(raw_sev)

    weight   := object.get(_severity_weight, severity, 1.0)
    mult     := _age_mult(age)
    pscore   := weight * mult * (estimate.hours / 4.0)

    item := {
        "hostname":       input.hostname,
        "framework":      input.framework,
        "violation":      violation_str,
        "effort_hours":   estimate.hours,
        "debt_category":  estimate.category,
        "complexity":     estimate.complexity,
        "severity":       severity,
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
    some cat in {"security", "compliance", "operational", "critical_infrastructure", "sovereignty", "technology_lifecycle"}
    cat_items := [item | some item in debt_items; item.debt_category == cat]
    totals := {
        "item_count":     count(cat_items),
        "effort_hours":   sum([i.effort_hours | some i in cat_items]),
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
        "hostname":             input.hostname,
        "framework":            input.framework,
        "assessment_timestamp": time.now_ns(),
        "total_violations":     count(input.violations),
        "total_effort_hours":   total_effort_hours,
        "debt_score":           debt_score,
        "critical_count":       critical_count,
        "high_count":           high_count,
        "by_category":          debt_by_category,
        "items":                [item | some item in debt_items]
    }
}
