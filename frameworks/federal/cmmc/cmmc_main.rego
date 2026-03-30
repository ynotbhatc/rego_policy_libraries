package cmmc

import rego.v1

# =============================================================================
# CMMC 2.0 — Master Compliance Orchestrator
# Cybersecurity Maturity Model Certification
# DoD Defense Federal Acquisition Regulation Supplement (DFARS)
# NIST SP 800-171 Rev 2 — 14 Domains, 110 Practices
#
# Domains:
#   3.1  AC  — Access Control                  (22 practices, L1+L2)
#   3.2  AT  — Awareness & Training            (3 practices,  L2)
#   3.3  AU  — Audit & Accountability          (9 practices,  L2)
#   3.4  CM  — Configuration Management        (9 practices,  L2)
#   3.5  IA  — Identification & Authentication (11 practices, L1+L2)
#   3.6  IR  — Incident Response               (3 practices,  L2)
#   3.7  MA  — Maintenance                     (6 practices,  L2)
#   3.8  MP  — Media Protection                (9 practices,  L2)
#   3.9  PS  — Personnel Security              (2 practices,  L2)
#   3.10 PE  — Physical Protection             (6 practices,  L1+L2)
#   3.11 RM  — Risk Assessment                 (3 practices,  L2)
#   3.12 CA  — Security Assessment             (4 practices,  L2)
#   3.13 SC  — System & Comm. Protection       (16 practices, L1+L2)
#   3.14 SI  — System & Info. Integrity        (7 practices,  L1+L2)
# =============================================================================

# ---------------------------------------------------------------------------
# Domain compliance reports (delegated to submodules)
# ---------------------------------------------------------------------------

ac_report  := data.cmmc.access_control.compliance_report
at_report  := data.cmmc.awareness_training.compliance_report
au_report  := data.cmmc.audit_accountability.compliance_report
cm_report  := data.cmmc.configuration_management.compliance_report
ia_report  := data.cmmc.identification_authentication.compliance_report
ir_report  := data.cmmc.incident_response.compliance_report
ma_report  := data.cmmc.maintenance.compliance_report
mp_report  := data.cmmc.media_protection.compliance_report
ps_report  := data.cmmc.personnel_security.compliance_report
pe_report  := data.cmmc.physical_protection.compliance_report
rm_report  := data.cmmc.risk_assessment.compliance_report
ca_report  := data.cmmc.security_assessment.compliance_report
sc_report  := data.cmmc.system_communications_protection.compliance_report
si_report  := data.cmmc.system_information_integrity.compliance_report

# ---------------------------------------------------------------------------
# Aggregate violations across all 14 domains
# ---------------------------------------------------------------------------

# Convert set-based violations (legacy modules) to arrays
ac_violations  := [v | some v in data.cmmc.access_control.violations]
cm_violations  := [v | some v in data.cmmc.configuration_management.violations]
ir_violations  := [v | some v in data.cmmc.incident_response.violations]

# New modules expose violations as arrays via compliance_report
at_violations  := at_report.violations
au_violations  := au_report.violations
ia_violations  := ia_report.violations
ma_violations  := ma_report.violations
mp_violations  := mp_report.violations
ps_violations  := ps_report.violations
pe_violations  := pe_report.violations
rm_violations  := rm_report.violations
ca_violations  := ca_report.violations
sc_violations  := sc_report.violations
si_violations  := si_report.violations

# Aggregate in pairs (array.concat takes exactly 2 args)
violations_ac_at := array.concat(ac_violations, at_violations)
violations_au_cm := array.concat(au_violations, cm_violations)
violations_ia_ir := array.concat(ia_violations, ir_violations)
violations_ma_mp := array.concat(ma_violations, mp_violations)
violations_ps_pe := array.concat(ps_violations, pe_violations)
violations_rm_ca := array.concat(rm_violations, ca_violations)
violations_sc_si := array.concat(sc_violations, si_violations)

violations_group1 := array.concat(violations_ac_at, violations_au_cm)
violations_group2 := array.concat(violations_ia_ir, violations_ma_mp)
violations_group3 := array.concat(violations_ps_pe, violations_rm_ca)

violations_half1 := array.concat(violations_group1, violations_group2)
violations_half2 := array.concat(violations_group3, violations_sc_si)

all_violations := array.concat(violations_half1, violations_half2)

# ---------------------------------------------------------------------------
# Domain compliance booleans
# ---------------------------------------------------------------------------

default ac_compliant := false
ac_compliant if ac_report.compliant == true

default at_compliant := false
at_compliant if at_report.compliant == true

default au_compliant := false
au_compliant if au_report.compliant == true

default cm_compliant := false
cm_compliant if cm_report.compliant == true

default ia_compliant := false
ia_compliant if ia_report.compliant == true

default ir_compliant := false
ir_compliant if ir_report.compliant == true

default ma_compliant := false
ma_compliant if ma_report.compliant == true

default mp_compliant := false
mp_compliant if mp_report.compliant == true

default ps_compliant := false
ps_compliant if ps_report.compliant == true

default pe_compliant := false
pe_compliant if pe_report.compliant == true

default rm_compliant := false
rm_compliant if rm_report.compliant == true

default ca_compliant := false
ca_compliant if ca_report.compliant == true

default sc_compliant := false
sc_compliant if sc_report.compliant == true

default si_compliant := false
si_compliant if si_report.compliant == true

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

domain_results := [
    ac_compliant,
    at_compliant,
    au_compliant,
    cm_compliant,
    ia_compliant,
    ir_compliant,
    ma_compliant,
    mp_compliant,
    ps_compliant,
    pe_compliant,
    rm_compliant,
    ca_compliant,
    sc_compliant,
    si_compliant,
]

passing_domains  := count([d | some d in domain_results; d == true])
total_domains    := 14

compliance_score := round((passing_domains / total_domains) * 100)

# ---------------------------------------------------------------------------
# Practice counts across all domains
# ---------------------------------------------------------------------------

total_practices := 110   # NIST SP 800-171 Rev 2 total

practices_passing := sum([ac_report.passing, at_report.passing, au_report.passing,
    cm_report.passing, ia_report.passing, ir_report.passing, ma_report.passing,
    mp_report.passing, ps_report.passing, pe_report.passing, rm_report.passing,
    ca_report.passing, sc_report.passing, si_report.passing])

practices_failing := total_practices - practices_passing

# ---------------------------------------------------------------------------
# Overall compliance
# ---------------------------------------------------------------------------

default cmmc_level_1_compliant := false
cmmc_level_1_compliant if {
    # Level 1 practices: AC (3.1.1-3.1.2), IA (3.5.1-3.5.2),
    #                    MP (none at L1), PE (3.10.1-3.10.2),
    #                    SC (3.13.1, 3.13.5), SI (3.14.1-3.14.5)
    ac_report.compliant == true
    ia_report.compliant == true
    pe_report.compliant == true
    sc_report.compliant == true
    si_report.compliant == true
}

default cmmc_level_2_compliant := false
cmmc_level_2_compliant if count(all_violations) == 0

default compliant := false
compliant if count(all_violations) == 0

# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

cmmc_compliance_report := {
    "standard":              "CMMC 2.0",
    "regulation":            "32 CFR Part 170 / DFARS 252.204-7021",
    "nist_sp":               "NIST SP 800-171 Rev 2",
    "compliant":             compliant,
    "level_1_compliant":     cmmc_level_1_compliant,
    "level_2_compliant":     cmmc_level_2_compliant,
    "compliance_score":      compliance_score,
    "total_domains":         total_domains,
    "domains_passing":       passing_domains,
    "domains_failing":       total_domains - passing_domains,
    "total_practices":       total_practices,
    "practices_passing":     practices_passing,
    "practices_failing":     practices_failing,
    "total_violations":      count(all_violations),
    "violations":            all_violations,
    "domains": {
        "3.1_access_control":                   ac_report,
        "3.2_awareness_training":               at_report,
        "3.3_audit_accountability":             au_report,
        "3.4_configuration_management":         cm_report,
        "3.5_identification_authentication":    ia_report,
        "3.6_incident_response":                ir_report,
        "3.7_maintenance":                      ma_report,
        "3.8_media_protection":                 mp_report,
        "3.9_personnel_security":               ps_report,
        "3.10_physical_protection":             pe_report,
        "3.11_risk_assessment":                 rm_report,
        "3.12_security_assessment":             ca_report,
        "3.13_system_communications":           sc_report,
        "3.14_system_information_integrity":    si_report,
    },
}
