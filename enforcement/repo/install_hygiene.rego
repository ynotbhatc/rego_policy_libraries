# Install-configuration hygiene — keep one environment's addresses and
# credentials out of another environment's install.
#
# WHAT THIS IS FOR
#
# A repository that ships an installer accumulates the maintainer's own
# addresses and passwords: a hostname in a README, a fallback password in a
# playbook, a checked-in config file pointing at the lab. Each one is harmless
# where it was written and none of them are harmless when a customer clones the
# repository and runs it. This encodes the four ways it happens.
#
# GENERIC BY CONSTRUCTION
#
# Nothing here names a specific site. The addresses, the credential literals,
# the protected paths and the allowlist all arrive as input, so any project can
# use this by supplying its own. That is deliberate: this library is consumed
# by more than one product and must not carry any one deployment's specifics.
#
# THE FOURTH RULE IS THE ONE THAT MATTERS
#
# AAC-CFG-003 checks whether a file is TRACKED, not what is in it. The defect
# that motivated this policy was a config file listed in .gitignore AND tracked
# by git — and git ignores .gitignore for files it already tracks, so the entry
# did nothing. The file kept shipping with the maintainer's addresses, every
# clone inherited them, and every local edit was a staged lab value waiting to
# be committed. A content scan cannot see that; only a tracked-ness check can.
#
# INPUT — two shapes, two entry points
#
#   Per-file content scan (AAC-CFG-001/002/004):
#     input.path                string   repo-relative path
#     input.lines[]             array    [{"n": <int>, "text": <string>}, ...]
#     input.lab_addresses[]     array    addresses that belong to one site only
#     input.banned_credentials[] array   credential literals that must not ship
#     input.allowlist[]         array    path prefixes exempt from 001/002
#
#   Repository-wide tracked-file check (AAC-CFG-003):
#     input.tracked_files[]     array    every path git currently tracks
#     input.must_be_untracked[] array    operator-owned config paths
#
# OPA query paths:
#   /v1/data/aac/repo/install_hygiene/violation
#   /v1/data/aac/repo/install_hygiene/tracking_violation

package aac.repo.install_hygiene

import rego.v1

path_label := input.path

default path_label := "<file>"

lab_addresses := object.get(input, "lab_addresses", [])

banned_credentials := object.get(input, "banned_credentials", [])

allowlist := object.get(input, "allowlist", [])

# A file is exempt when its path starts with an allowlisted prefix. Prefixes are
# supplied explicitly rather than inferred: an allowlist that guesses is an
# allowlist nobody can audit.
allowlisted if {
	some prefix in allowlist
	startswith(path_label, prefix)
}

lines := object.get(input, "lines", [])

# ── AAC-CFG-001 — no site-specific address in a shipped file ────────────────
violation contains msg if {
	not allowlisted
	some line in lines
	some addr in lab_addresses
	contains(line.text, addr)
	msg := sprintf(
		"AAC-CFG-001: %s:%v: address %s belongs to one environment — resolve it through the install inventory instead of naming it here",
		[path_label, line.n, addr],
	)
}

# ── AAC-CFG-002 — no working credential in a shipped file ──────────────────
# Applies to templates and documentation as much as to code. A password in a
# README is a password a customer will paste, and an "e.g." in an .example file
# is still the real credential.
violation contains msg if {
	not allowlisted
	some line in lines
	some cred in banned_credentials
	contains(line.text, cred)
	msg := sprintf(
		"AAC-CFG-002: %s:%v: credential literal %q must not ship — use a placeholder and source the real value from an AAP credential or an encrypted vault file",
		[path_label, line.n, cred],
	)
}

# ── AAC-CFG-004 — a secret must not have a fallback default ────────────────
# `password | default('something')` fails OPEN: when the credential is missing
# the run does not stop, it proceeds with whatever was baked in. That is how a
# customer's install ends up authenticating with the maintainer's password.
# Matches Ansible/Jinja `default(...)` and shell `${VAR:-...}` on a name that
# looks like a secret.
# The name being ASSIGNED must look like a secret — not merely some word on the
# line. Scanning the whole line flagged
#     max_days: "{{ ... 'PASS_MAX_DAYS' ... | default('99999') }}"
# which parses a password-AGING policy and holds no credential at all. A rule
# that flags password policy alongside real passwords trains people to ignore
# it, so the target is matched specifically.
# The keyword must END the identifier. Allowing a trailing `\w*` matched
# `password_authentication` and `permit_empty_passwords` -- sshd CONFIG FIELDS,
# not credentials. Acting on those replaced `| default('not set')` with
# `| mandatory` and broke fact collection on every host that relies on sshd
# defaults, which is most of them. A name that merely CONTAINS "password" is
# usually a setting about passwords; a name that ENDS with it is the secret.
secret_assignment(text) if {
	regex.match(`(?i)^\s*[-\s]*["']?[\w.]*?(password|passwd|secret|token|api_?key)["']?\s*[:=]`, text)
}

# A purely numeric fallback is a duration, port or retry count, never a
# credential. Excluded so the rule stays believable.
numeric_default(text) if regex.match(`\|\s*default\(\s*['"][0-9]+['"][^)]*\)`, text)

violation contains msg if {
	not allowlisted
	some line in lines
	secret_assignment(line.text)
	# `[^)]*` after the literal so the two-argument form — default('x', true),
	# which is how Ansible spells "treat empty as unset" — is caught too. A
	# pattern requiring `)` immediately after the quote missed every one of them.
	regex.match(`\|\s*default\(\s*['"][^'"]+['"][^)]*\)`, line.text)
	not numeric_default(line.text)
	msg := sprintf(
		"AAC-CFG-004: %s:%v: secret has a fallback default — this fails open. Use `| mandatory` so a missing credential stops the run instead of silently authenticating with a value baked into the repository",
		[path_label, line.n],
	)
}

# For shell, the secret-ness is in the variable name inside ${NAME:-...}, which
# is often mid-line (`... PASSWORD '${READER_PASSWORD:-hunter2}'`), so the
# assignment-target test above does not apply.
violation contains msg if {
	not allowlisted
	some line in lines
	# `[^}]+` not `[^}]*`: an EMPTY default (`${VAR:-}`) is not a fallback
	# credential, it is the standard `set -u`-safe way to read a maybe-unset
	# variable so the next line can check it and print real guidance. Flagging
	# it pushed scripts toward `${VAR:?}`, which aborts with bash's terse
	# message BEFORE the script's own error text can run -- strictly worse.
	# Only a non-empty fallback is a shipped credential.
	some m in regex.find_n(`\$\{[A-Za-z_][A-Za-z0-9_]*:-[^}]+\}`, line.text, -1)
	# Shell names abbreviate (GRAFANA_PASS, DB_PASSWD), so match on an
	# underscore-delimited SEGMENT rather than a substring. Substring matching
	# would also catch BYPASS_CHECK and PASSED_COUNT; segment matching does not.
	# Same rule as above: the keyword must be the LAST segment. Allowing
	# trailing segments matched `${TOKEN_NOTE:-}` -- a display string, not a
	# credential -- and turning it into `${TOKEN_NOTE:?}` aborted the script on
	# its normal path, because that note is only set on a fallback branch.
	regex.match(`(?i)\$\{(\w+_)?(password|passwd|pass|secret|token|api_?key|credential):-`, m)
	msg := sprintf(
		"AAC-CFG-004: %s:%v: secret has a shell fallback default (%s) — this fails open. Use ${VAR:?message} so a missing credential stops the run",
		[path_label, line.n, m],
	)
}

# ── AAC-CFG-003 — operator config must not be tracked ───────────────────────
# The rule a content scan cannot express. Checked once for the repository.
tracking_violation contains msg if {
	some p in object.get(input, "must_be_untracked", [])
	some tracked in object.get(input, "tracked_files", [])
	tracked == p
	msg := sprintf(
		"AAC-CFG-003: %s is tracked by git but holds one environment's values. Untrack it (`git rm --cached %s`) and ship only the .example — a .gitignore entry has NO effect on an already-tracked file, which is exactly how this was missed before",
		[p, p],
	)
}

# ── Reports ─────────────────────────────────────────────────────────────────

default compliant := false

compliant if count(violation) == 0

compliance_report := {
	"policy": "Install configuration hygiene",
	"path": path_label,
	"lines_scanned": count(lines),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

default tracking_compliant := false

tracking_compliant if count(tracking_violation) == 0

tracking_report := {
	"policy": "Install configuration hygiene — tracked files",
	"tracked_count": count(object.get(input, "tracked_files", [])),
	"violations": tracking_violation,
	"violation_count": count(tracking_violation),
	"compliant": tracking_compliant,
}
