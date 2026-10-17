# METADATA
# title: "Corporate Password Policy Implementation"
# custom:
#   class: compliance
#   framework: corporate
#   source: aac
#   domains: [corporate]
#   coverage:
#     checks: 3
#     cited: 3
#     density: sparse
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package corporate.password

import rego.v1

# Corporate Password Policy Implementation
# Based on typical enterprise password requirements
# Maps corporate policy documents to technical enforcement

# Date normaliser: RFC3339 string or epoch nanoseconds; anything else is
# undefined, so callers fail closed (a missing or unparseable date is never a pass).
date_ns(v) := n if {
    is_string(v)
    n := time.parse_rfc3339_ns(v)
}

date_ns(v) := v if is_number(v)

# Rules used as values inside the violations / score arrays must be false, not
# undefined, or the whole array is undefined and a failing check disappears.
default length_requirements_met := false
default complexity_requirements_met := false
default history_requirements_met := false
default age_requirements_met := false

# Main password policy evaluation
password_compliant if {
    length_requirements_met
    complexity_requirements_met
    history_requirements_met
    age_requirements_met
    not contains_forbidden_patterns
}

# Password Length Requirements
# Corporate Policy: "Passwords must be at least 12 characters for standard users, 14 for privileged accounts"
length_requirements_met if {
    input.password.length >= minimum_length_for_role
}

minimum_length_for_role := 14 if {
    input.user.role in ["admin", "privileged", "service_account", "database_admin"]
}

minimum_length_for_role := 12 if {
    input.user.role in ["standard", "contractor", "guest"]
}

minimum_length_for_role := 16 if {
    input.user.role in ["system_admin", "security_admin", "compliance_officer"]
}

# Password Complexity Requirements
# Corporate Policy: "Passwords must contain characters from at least 3 of 4 character classes"
complexity_requirements_met if {
    character_classes_used >= 3
}

character_classes_used = count([class |
    class_name := ["uppercase", "lowercase", "digits", "special"][_]
    character_class_present(input.password.value, class_name)
    class := class_name
])

character_class_present(password, "uppercase") if {
    regex.match(`[A-Z]`, password)
}

character_class_present(password, "lowercase") if {
    regex.match(`[a-z]`, password)
}

character_class_present(password, "digits") if {
    regex.match(`[0-9]`, password)
}

character_class_present(password, "special") if {
    regex.match(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`, password)
}

# Password History Requirements
# Corporate Policy: "Users cannot reuse their last 12 passwords"
history_requirements_met if {
    not password_in_history
}

# password_in_history — expects the caller to have pre-hashed input.password.value
# with the same algorithm used to populate input.user.password_history[].hash.
# Rego is NOT the place to compute password hashes; the fact-collection layer
# (Ansible playbook / PAM history reader) must provide comparable hash values.
password_in_history if {
    some i
    input.user.password_history[i].hash == input.password.value_hash
}

# Password Age Requirements
# Corporate Policy: "Passwords must be changed every 90 days, cannot be changed more than once per day"
age_requirements_met if {
    # The age must be knowable: a missing or unparseable last_password_change is
    # not a pass (days_since_last_change would be undefined, so "not expired").
    days_since_last_change
    not password_expired
    not changed_too_recently
}

password_expired if {
    days_since_last_change > maximum_password_age
}

days_since_last_change := (time.now_ns() - date_ns(input.user.last_password_change)) / (24 * 60 * 60 * 1000000000)

# Roles not listed below get the general 90-day rule (previously undefined, which
# made password_expired undefined and the age check pass).
default maximum_password_age := 90

maximum_password_age := 90 if {
    input.user.role in ["standard", "contractor", "guest"]
}

maximum_password_age := 60 if {
    input.user.role in ["admin", "privileged", "service_account"]
}

maximum_password_age := 45 if {
    input.user.role in ["system_admin", "security_admin", "compliance_officer"]
}

changed_too_recently if {
    days_since_last_change < 1
}

# Forbidden Password Patterns
# Corporate Policy: "Passwords cannot contain dictionary words, personal information, or common patterns"
contains_forbidden_patterns if {
    contains_personal_info
}

contains_forbidden_patterns if {
    contains_company_info
}

contains_forbidden_patterns if {
    contains_sequential_chars
}

contains_forbidden_patterns if {
    contains_repeated_chars
}

contains_forbidden_patterns if {
    is_common_password
}

# Personal Information Checks
contains_personal_info if {
    personal_fields := ["username", "first_name", "last_name", "employee_id", "email"]
    some field in personal_fields
    user_field := object.get(input.user, field, "")
    user_field != ""
    contains(lower(input.password.value), lower(user_field))
}

# Company Information Checks
contains_company_info if {
    company_terms := ["company", "corp", "inc", "llc", input.organization.name]
    some company_term in company_terms
    contains(lower(input.password.value), lower(company_term))
}

# Sequential Character Detection
contains_sequential_chars if {
    chars := regex.find_n(`(?s).`, lower(input.password.value), -1)
    count(chars) >= 3
    some i in numbers.range(0, count(chars) - 3)
    window := concat("", array.slice(chars, i, i + 3))
    some alphabet in ["abcdefghijklmnopqrstuvwxyz", "0123456789"]
    contains(alphabet, window)
}

# Repeated Character Detection
contains_repeated_chars if {
    chars := regex.find_n(`(?s).`, input.password.value, -1)
    some char in chars
    char_count := count([c | some c in chars; c == char])
    char_count > 3  # More than 3 of the same character
}

# Common Password Dictionary
is_common_password if {
    lower(input.password.value) in common_passwords
}

common_passwords := {
    "password", "123456", "123456789", "qwerty", "abc123", "password123",
    "admin", "letmein", "welcome", "monkey", "dragon", "master",
    "shadow", "12345678", "football", "baseball", "trustno1"
}

# Service Account Specific Rules
# Corporate Policy: "Service accounts have additional restrictions"
service_account_compliant if {
    input.user.role != "service_account"
}

service_account_compliant if {
    input.user.role == "service_account"
    service_account_length_met
    service_account_entropy_met
    not contains_predictable_patterns
}

service_account_length_met if {
    input.password.length >= 20
}

service_account_entropy_met if {
    password_entropy >= 60
}

# Entropy calculation (simplified approximation)
# Estimates entropy based on character set size and password length
password_entropy := entropy if {
    chars := regex.find_n(`(?s).`, input.password.value, -1)
    unique_chars := {char | some char in chars}

    # Estimate bits per character based on character diversity
    # Lowercase: ~4.7 bits, Uppercase: ~4.7 bits, Digits: ~3.3 bits, Symbols: ~5 bits
    # We approximate using character set size: log2(charset_size) ≈ charset_size/3 for simplicity
    charset_size := count(unique_chars)
    bits_per_char := charset_size / 3

    # Total entropy = bits per position * number of positions
    entropy := bits_per_char * count(chars)
}

# Three identical characters in a row. (The old `(.)\1{2,}` back-reference is not
# valid RE2, so it never matched.)
contains_predictable_patterns if {
    chars := regex.find_n(`(?s).`, input.password.value, -1)
    count(chars) >= 3
    some i in numbers.range(0, count(chars) - 3)
    chars[i] == chars[i + 1]
    chars[i + 1] == chars[i + 2]
}

no_forbidden_patterns if {
    not contains_forbidden_patterns
}

default no_forbidden_patterns := false

contains_predictable_patterns if {
    regex.match(`(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)`, lower(input.password.value))
}

# Temporary Password Rules
# Corporate Policy: "Temporary passwords must be changed on first login"
temporary_password_compliant if {
    not input.password.is_temporary
}

temporary_password_compliant if {
    input.password.is_temporary
    input.user.must_change_password
    temporary_password_not_expired
}

temporary_password_not_expired if {
    temp_age_days := (time.now_ns() - date_ns(input.password.created_date)) / (24 * 60 * 60 * 1000000000)
    temp_age_days <= 7  # Temporary passwords expire in 7 days
}

# Multi-Factor Authentication Integration
# Corporate Policy: "Strong passwords may reduce MFA frequency requirements"
mfa_frequency_reduced if {
    password_strength_score >= 85
    input.user.mfa_enabled
}

password_strength_score := score if {
    length_score := min([100, (input.password.length * 5)])
    complexity_score := character_classes_used * 20
    entropy_score := min([40, password_entropy])

    score := length_score + complexity_score + entropy_score
}

# Compliance Integration
# Map password policy to compliance frameworks
pci_dss_password_compliant if {
    password_compliant
    input.user.access_level in ["cardholder_data", "payment_processing"]
    input.password.length >= 12
    character_classes_used >= 3
}

sox_password_compliant if {
    password_compliant
    input.user.access_level in ["financial_reporting", "sox_relevant"]
    input.password.length >= 14
    maximum_password_age <= 60
}

# Password Policy Violations and Remediation
length_requirement_text := sprintf("Minimum %d characters", [minimum_length_for_role]) if {
    minimum_length_for_role
} else := "Minimum length for the user's role (role not recognised)"

password_violations := violations if {
    violations = [violation |
        checks = [
            {"check": "length", "passed": length_requirements_met, "requirement": length_requirement_text},
            {"check": "complexity", "passed": complexity_requirements_met, "requirement": "At least 3 character classes"},
            {"check": "history", "passed": history_requirements_met, "requirement": "Cannot reuse last 12 passwords"},
            {"check": "age", "passed": age_requirements_met, "requirement": sprintf("Must change every %d days", [maximum_password_age])},
            {"check": "forbidden_patterns", "passed": no_forbidden_patterns, "requirement": "No personal info or common patterns"}
        ]
        check = checks[_]
        not check.passed
        violation = {
            "type": check.check,
            "requirement": check.requirement,
            "current_status": "non_compliant",
            "remediation": get_remediation(check.check)
        }
    ]
}

get_remediation("length") := "Increase password length to meet role requirements"
get_remediation("complexity") := "Add uppercase, lowercase, numbers, or special characters"
get_remediation("history") := "Choose a password not used in the last 12 changes"
get_remediation("age") := "Password has expired and must be changed"
get_remediation("forbidden_patterns") := "Remove personal information and common patterns"

# Password Policy Score (0-100)
password_policy_score := score if {
    total_checks := 5
    passed_checks = count([check |
        checks = [
            length_requirements_met,
            complexity_requirements_met,
            history_requirements_met,
            age_requirements_met,
            no_forbidden_patterns
        ]
        check = checks[_]
        check == true
    ])
    score := (passed_checks * 100) / total_checks
}

# Policy Metadata for Automation
policy_metadata := {
    "policy_name": "Corporate Password Policy",
    "version": "2.1",
    "effective_date": "2025-01-01",
    "last_updated": "2025-10-05",
    "policy_owner": "Chief Information Security Officer",
    "compliance_frameworks": ["PCI DSS", "SOX", "ISO 27001"],
    "enforcement_level": "mandatory",
    "grace_period_days": 30,
    "exception_approval_required": true
}

# NOTE: A fake `hash_password()` helper previously lived here that returned
# `"hash_" + password` (literally a prefix + plaintext). It was called from the
# password-reuse check above and would have silently produced FALSE COMPLIANCE
# in any real deployment (real password history stores bcrypt/argon2/sha512-crypt
# hashes; the fake would never match). Removed. The reuse check now expects the
# caller to pre-hash `input.password.value` using the same algorithm as the
# password history and pass it in as `input.password.value_hash`.