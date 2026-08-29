# Tests for install-configuration hygiene.
#
# The fixtures are the actual defects this policy was written after, not
# invented ones: a lab address in an install README, the maintainer's Grafana
# password used as a fallback default, a credential left in an .example file as
# "e.g.", and a config file that was gitignored and tracked at the same time.

package aac.repo.install_hygiene_test

import data.aac.repo.install_hygiene as ih
import rego.v1

# ── helpers ──────────────────────────────────────────────────────────────────

LAB := ["192.0.2.10", "192.0.2.11"]

CREDS := ["Sup3rSecret", "admin123"]

file(path, texts) := {
	"path": path,
	"lines": [line | some i, t in texts; line := {"n": i + 1, "text": t}],
	"lab_addresses": LAB,
	"banned_credentials": CREDS,
	"allowlist": ["config/profiles/lab.yml", "tooling/local/"],
}

has(violations, code) if {
	some v in violations
	contains(v, code)
}

# ── AAC-CFG-001 — site-specific addresses ────────────────────────────────────

test_lab_address_in_a_readme_violates if {
	v := ih.violation with input as file("install/README.md", [
		"# Install",
		"Point the controller at 192.0.2.10 and run the playbook.",
	])
	has(v, "AAC-CFG-001")
}

# The message must carry the line number — a reviewer needs to find it.
test_address_violation_names_the_line if {
	v := ih.violation with input as file("install/README.md", [
		"first",
		"second",
		"host: 192.0.2.10",
	])
	some m in v
	contains(m, "install/README.md:3")
}

test_placeholder_host_passes if {
	v := ih.violation with input as file("install/README.md", ["host: <aac-host>"])
	not has(v, "AAC-CFG-001")
}

# The lab's own profile is where these addresses legitimately live.
test_allowlisted_path_is_exempt if {
	v := ih.violation with input as file("config/profiles/lab.yml", ["host: 192.0.2.10"])
	not has(v, "AAC-CFG-001")
}

# A prefix allowlist must cover the whole subtree, not just an exact path.
test_allowlist_covers_a_subtree if {
	v := ih.violation with input as file("tooling/local/scripts/reset.sh", ["ssh me@192.0.2.11"])
	not has(v, "AAC-CFG-001")
}

# ── AAC-CFG-002 — shipped credentials ────────────────────────────────────────

test_credential_in_a_readme_violates if {
	v := ih.violation with input as file("install/README.md", ["Login: admin / Sup3rSecret"])
	has(v, "AAC-CFG-002")
}

# An .example file is the most tempting place to leave a real value and the
# worst, because it reads as authoritative. "e.g. <real password>" still ships
# the password.
test_credential_as_an_example_still_violates if {
	v := ih.violation with input as file("config/secrets.yml.example", [
		"grafana_admin_password:   <admin password — e.g. Sup3rSecret>",
	])
	has(v, "AAC-CFG-002")
}

test_placeholder_credential_passes if {
	v := ih.violation with input as file("config/secrets.yml.example", [
		"grafana_admin_password: PLACEHOLDER",
	])
	not has(v, "AAC-CFG-002")
}

# ── AAC-CFG-004 — fail-open secret defaults ──────────────────────────────────

test_jinja_default_on_a_password_violates if {
	v := ih.violation with input as file("playbooks/deploy.yml", [
		"    grafana_admin_password: \"{{ grafana_admin_password | default('Sup3rSecret') }}\"",
	])
	has(v, "AAC-CFG-004")
}

test_mandatory_instead_of_default_passes if {
	v := ih.violation with input as file("playbooks/deploy.yml", [
		"    grafana_admin_password: \"{{ grafana_admin_password | mandatory }}\"",
	])
	not has(v, "AAC-CFG-004")
}

test_shell_fallback_on_a_password_violates if {
	v := ih.violation with input as file("scripts/check.sh", [
		"GRAFANA_PASS=\"${GRAFANA_PASS:-Sup3rSecret}\"",
	])
	has(v, "AAC-CFG-004")
}

test_shell_required_form_passes if {
	v := ih.violation with input as file("scripts/check.sh", [
		"GRAFANA_PASS=\"${GRAFANA_PASS:?set GRAFANA_PASS}\"",
	])
	not has(v, "AAC-CFG-004")
}

# A default on something that is not a secret is ordinary good practice and
# must not be flagged — a rule that cries wolf gets switched off.
test_default_on_a_non_secret_passes if {
	v := ih.violation with input as file("playbooks/deploy.yml", [
		"    listen_port: \"{{ listen_port | default('8080') }}\"",
	])
	not has(v, "AAC-CFG-004")
}

# ── AAC-CFG-003 — tracked operator config ────────────────────────────────────
# The defect a content scan structurally cannot catch.

test_tracked_operator_config_violates if {
	v := ih.tracking_violation with input as {
		"tracked_files": ["README.md", "config/site_config.yml"],
		"must_be_untracked": ["config/site_config.yml"],
	}
	has(v, "AAC-CFG-003")
}

test_untracked_operator_config_passes if {
	v := ih.tracking_violation with input as {
		"tracked_files": ["README.md", "config/site_config.yml.example"],
		"must_be_untracked": ["config/site_config.yml"],
	}
	count(v) == 0
}

# The .example must stay tracked — untracking it would leave an operator with
# no template at all, so the rule must match exactly and not by prefix.
test_example_file_is_not_confused_with_the_real_one if {
	v := ih.tracking_violation with input as {
		"tracked_files": ["config/site_config.yml.example"],
		"must_be_untracked": ["config/site_config.yml"],
	}
	count(v) == 0
}

# ── reports ──────────────────────────────────────────────────────────────────

test_clean_file_is_compliant if {
	r := ih.compliance_report with input as file("install/README.md", ["host: <aac-host>"])
	r.compliant == true
	r.violation_count == 0
	r.lines_scanned == 1
}

# A caller that omits `path` must still get a usable report rather than the
# empty object an undefined field collapses to.
test_report_survives_a_missing_path if {
	r := ih.compliance_report with input as {"lines": [{"n": 1, "text": "ok"}]}
	r.path == "<file>"
	count(r) > 0
}

test_tracking_report_is_populated if {
	r := ih.tracking_report with input as {
		"tracked_files": ["a", "b"],
		"must_be_untracked": ["c"],
	}
	r.tracked_count == 2
	r.compliant == true
}

# Password *policy* is not a password. This line parses PASS_MAX_DAYS from
# /etc/login.defs; scanning the whole line for the word "password" flagged it,
# and a rule that flags password policy next to real passwords is a rule people
# learn to ignore.
test_password_aging_policy_is_not_a_secret if {
	v := ih.violation with input as file("roles/facts/tasks/users.yml", [
		"    max_days: \"{{ raw.stdout | regex_search('PASS_MAX_DAYS\\\\s+(\\\\d+)') | default('99999') }}\"",
	])
	not has(v, "AAC-CFG-004")
}

# A numeric fallback is a timeout, port or retry count.
test_numeric_default_on_a_secretish_name_passes if {
	v := ih.violation with input as file("playbooks/x.yml", [
		"    token_ttl_seconds: \"{{ token_ttl_seconds | default('3600') }}\"",
	])
	not has(v, "AAC-CFG-004")
}

# The shell form is usually mid-line, so the secret-ness must come from the
# variable name inside ${...} rather than from the assignment target.
test_shell_secret_default_midline_violates if {
	v := ih.violation with input as file("scripts/install.sh", [
		"    CREATE ROLE reader LOGIN PASSWORD '${READER_PASSWORD:-changeme}';",
	])
	has(v, "AAC-CFG-004")
}

test_shell_non_secret_default_passes if {
	v := ih.violation with input as file("scripts/install.sh", [
		"    PORT=\"${PORT:-5432}\"",
	])
	not has(v, "AAC-CFG-004")
}

# Substring matching on the variable name would flag these; segment matching
# must not.
test_bypass_is_not_a_password if {
	v := ih.violation with input as file("scripts/x.sh", ["MODE=\"${BYPASS:-off}\""])
	not has(v, "AAC-CFG-004")
}
