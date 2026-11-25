# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# Requirement (owner ruling, audit 2026-11-24 round 3): "a STIG check requires what DISA's check text
# requires".
#
# Source of the banner and of the check sentences quoted below: DISA Microsoft Windows Server 2022 STIG V2R11
# (Manual XCCDF, public.cyber.mil STIG library), rule WN22-SO-000130: "If the following registry value does not
# exist or is not configured as specified, this is a finding ... Value Name: LegalNoticeText ... Value Type:
# REG_SZ", followed by the Standard Mandatory DoD Notice and Consent Banner (the text of DoDI 8500.01 /
# DoD CIO memo of 9 May 2008). The seven paragraphs below were compared programmatically with the check text
# of that XCCDF (whitespace-normalised, identical).
#
# The tree's green fixture is used by reference. It holds a placeholder banner today, so the passing baseline
# here is that fixture with the legal-notice value(s) set to what the check text requires (`base`); the test
# holds whether or not the fixture is corrected by the fix.

package stig.windows_server_2022_acceptance_r3

import rego.v1

fx := data.stig.windows_server_2022_test.green_fixture

sys_key := "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"

text_rule := "WN22-SO-000130"

banner_paragraphs := [
	"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.",
	"By using this IS (which includes any device attached to this IS), you consent to the following conditions:",
	"-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.",
	"-At any time, the USG may inspect and seize data stored on this IS.",
	"-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.",
	"-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.",
	"-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.",
]

banner := concat("\n\n", banner_paragraphs)

# This STIG release has no LegalNoticeCaption rule (none in the XCCDF, none in the module): nothing to add.
caption_patch := []

base := json.patch(fx, array.concat(
	[{"op": "add", "path": ["registry", sys_key, "LegalNoticeText"], "value": banner}],
	caption_patch,
))

open_ids(inp) := {f.stig_id |
	r := data.stig.windows_server_2022.main.compliance_report with input as inp
	some f in r.open_findings
}

compliant(inp) := c if {
	r := data.stig.windows_server_2022.main.compliance_report with input as inp
	c := r.compliant
}

# Requirement: the fixture with the exact banner is compliant with nothing open (regression guard).
test_baseline_with_the_exact_banner_passes if {
	compliant(base) == true
	count(open_ids(base)) == 0
}

# the same words with different line endings and spacing: a registry export, a GPO editor and a JSON
# collector do not agree on CRLF / LF or on runs of blanks, and the check text does not prescribe them
same_words := {
	"crlf": concat("\r\n\r\n", banner_paragraphs),
	"lf_single": concat("\n", banner_paragraphs),
	"one_line": concat(" ", banner_paragraphs),
	"collapsed": regex.replace(banner, `\s+`, " "),
	"doubled_spaces": replace(banner, " ", "  "),
	"trailing_newline": concat("", [concat("\r\n\r\n", banner_paragraphs), "\r\n"]),
}

# Requirement: the exact Standard Mandatory DoD Notice and Consent Banner passes WN22-SO-000130 whatever the line
# endings (CRLF or LF) and however runs of whitespace are written. Source: task list item 2(a); check text
# "configured as specified" gives the words, not the line endings.
test_exact_banner_passes_with_any_line_endings_and_spacing if {
	every _, text in same_words {
		inp := json.patch(base, [{"op": "replace", "path": ["registry", sys_key, "LegalNoticeText"], "value": text}])
		not text_rule in open_ids(inp)
		compliant(inp) == true
	}
}

# text that is not the banner "as specified"
not_the_banner := {
	"arbitrary": "Authorized users only. Activity may be monitored.",
	"fixture_placeholder": "<banner text as configured>",
	"first_two_paragraphs": concat("\n\n", array.slice(banner_paragraphs, 0, 2)),
	"last_paragraph_missing": concat("\n\n", array.slice(banner_paragraphs, 0, 6)),
	"last_sentence_missing": replace(banner, " See User Agreement for details.", ""),
	"cut_mid_sentence": substring(banner, 0, 600),
	"one_condition_dropped": concat("\n\n", array.concat(array.slice(banner_paragraphs, 0, 3), array.slice(banner_paragraphs, 4, 7))),
	"sentence_altered": replace(banner, "the USG may inspect and seize data", "the USG may not inspect or seize data"),
	"word_altered": replace(banner, "provided for USG-authorized use only", "provided for authorized use"),
}

# Requirement: an arbitrary non-empty string, a truncated banner and the banner with a sentence altered each
# open WN22-SO-000130 and the report is not compliant. Source: check text "does not exist or is not configured as
# specified, this is a finding"; audit finding "any non-empty LegalNoticeText passes".
test_text_that_is_not_the_banner_opens_the_rule if {
	every _, text in not_the_banner {
		text != banner
		inp := json.patch(base, [{"op": "replace", "path": ["registry", sys_key, "LegalNoticeText"], "value": text}])
		text_rule in open_ids(inp)
		compliant(inp) == false
	}
}

# ── every registry value a rule reads: absent or null is a finding ──────────────────────────────────────────

# [key path, value name] of every registry value the green fixture holds
leaves := [[k, n] | some k, vs in fx.registry; some n, _ in vs]

# ALLOW-LIST, initially EMPTY: stig ids of rules whose DISA check text says an ABSENT value is not a finding
# (for example "If the registry value does not exist, this is not a finding"). The implementer may add a rule
# id here ONLY with the check-text sentence quoted in their report, and as a comment on the entry; the
# integrator reviews every addition. Nothing else in this file may change. The list excuses the absent value
# only: null is "not collected" and is always a finding.
# Entries added by the integrator 2026-11-24 after extracting them from the DISA Manual XCCDF (Server 2022 V2R11):
# each rule's check-content says "(or if the Value Name does not exist)" and/or
# "If the registry value name below does not exist, this is not a finding."
absent_is_not_a_finding := {
	"WN22-CC-000130",
	"WN22-CC-000310",
	"WN22-CC-000320",
	"WN22-CC-000330",
	"WN22-CC-000400",
	"WN22-CC-000440",
	"WN22-UC-000010",
}

# The sweeps below run in 4 shards of `leaves` (leaf index modulo 4), so that no test runs long enough to meet
# the suite's per-test timeout on the oldest supported OPA. Every leaf is in exactly one shard; the shards are
# checked to cover `leaves` in test_the_shards_cover_every_registry_value.
shards := 4

shard(i) := [l | some j, l in leaves; j % shards == i]

test_the_shards_cover_every_registry_value if {
	count(leaves) >= 100
	every j, l in leaves {
		l in shard(j % shards)
	}
	sum([count(shard(i)) | some i in numbers.range(0, shards - 1)]) == count(leaves)
}

# the rule(s) that read a value (of the leaves given): those Open once it is replaced by something that is no
# registry value at all
readers_of(ls) := {l: ids |
	some l in ls
	ids := open_ids(json.patch(base, [{"op": "replace", "path": ["registry", l[0], l[1]], "value": {"r3": "not a registry value"}}]))
}

# Requirement: the sweep is not vacuous - every value of the fixture is read by at least one rule.
test_every_registry_value_is_read_by_a_rule_shard_0 if {
	count(leaves) >= 100
	rd := readers_of(shard(0))
	every l in shard(0) {
		count(rd[l]) >= 1
	}
}

test_every_registry_value_is_read_by_a_rule_shard_1 if {
	count(leaves) >= 100
	rd := readers_of(shard(1))
	every l in shard(1) {
		count(rd[l]) >= 1
	}
}

test_every_registry_value_is_read_by_a_rule_shard_2 if {
	count(leaves) >= 100
	rd := readers_of(shard(2))
	every l in shard(2) {
		count(rd[l]) >= 1
	}
}

test_every_registry_value_is_read_by_a_rule_shard_3 if {
	count(leaves) >= 100
	rd := readers_of(shard(3))
	every l in shard(3) {
		count(rd[l]) >= 1
	}
}

# Requirement: a registry value that a rule reads being ABSENT opens that rule and the report is not
# compliant, except for the rules on the allow-list above. Source: check text "If the following registry value
# does not exist or is not configured as specified, this is a finding"; task list item 2(c).
test_absent_registry_value_opens_the_reading_rule_shard_0 if {
	rd := readers_of(shard(0))
	every l in shard(0) {
		inp := json.remove(base, [["registry", l[0], l[1]]])
		r := data.stig.windows_server_2022.main.compliance_report with input as inp
		must := rd[l] - absent_is_not_a_finding
		must - {f.stig_id | some f in r.open_findings} == set()
		absent_verdict(must, r.compliant)
	}
}

test_absent_registry_value_opens_the_reading_rule_shard_1 if {
	rd := readers_of(shard(1))
	every l in shard(1) {
		inp := json.remove(base, [["registry", l[0], l[1]]])
		r := data.stig.windows_server_2022.main.compliance_report with input as inp
		must := rd[l] - absent_is_not_a_finding
		must - {f.stig_id | some f in r.open_findings} == set()
		absent_verdict(must, r.compliant)
	}
}

test_absent_registry_value_opens_the_reading_rule_shard_2 if {
	rd := readers_of(shard(2))
	every l in shard(2) {
		inp := json.remove(base, [["registry", l[0], l[1]]])
		r := data.stig.windows_server_2022.main.compliance_report with input as inp
		must := rd[l] - absent_is_not_a_finding
		must - {f.stig_id | some f in r.open_findings} == set()
		absent_verdict(must, r.compliant)
	}
}

test_absent_registry_value_opens_the_reading_rule_shard_3 if {
	rd := readers_of(shard(3))
	every l in shard(3) {
		inp := json.remove(base, [["registry", l[0], l[1]]])
		r := data.stig.windows_server_2022.main.compliance_report with input as inp
		must := rd[l] - absent_is_not_a_finding
		must - {f.stig_id | some f in r.open_findings} == set()
		absent_verdict(must, r.compliant)
	}
}

# `c` is the report's `compliant`, read once by the caller
absent_verdict(must, c) if {
	count(must) >= 1
	c == false
}

absent_verdict(must, _) if count(must) == 0

# Requirement: a registry value sent as null ("not collected") opens the rule that reads it; no exceptions.
# Source: evidence rule (AGENT_BRIEF.md) - missing or null evidence fails the control.
test_null_registry_value_opens_the_reading_rule_shard_0 if {
	rd := readers_of(shard(0))
	every l in shard(0) {
		inp := json.patch(base, [{"op": "replace", "path": ["registry", l[0], l[1]], "value": null}])
		r := data.stig.windows_server_2022.main.compliance_report with input as inp
		count(rd[l]) >= 1
		rd[l] - {f.stig_id | some f in r.open_findings} == set()
		r.compliant == false
	}
}

test_null_registry_value_opens_the_reading_rule_shard_1 if {
	rd := readers_of(shard(1))
	every l in shard(1) {
		inp := json.patch(base, [{"op": "replace", "path": ["registry", l[0], l[1]], "value": null}])
		r := data.stig.windows_server_2022.main.compliance_report with input as inp
		count(rd[l]) >= 1
		rd[l] - {f.stig_id | some f in r.open_findings} == set()
		r.compliant == false
	}
}

test_null_registry_value_opens_the_reading_rule_shard_2 if {
	rd := readers_of(shard(2))
	every l in shard(2) {
		inp := json.patch(base, [{"op": "replace", "path": ["registry", l[0], l[1]], "value": null}])
		r := data.stig.windows_server_2022.main.compliance_report with input as inp
		count(rd[l]) >= 1
		rd[l] - {f.stig_id | some f in r.open_findings} == set()
		r.compliant == false
	}
}

test_null_registry_value_opens_the_reading_rule_shard_3 if {
	rd := readers_of(shard(3))
	every l in shard(3) {
		inp := json.patch(base, [{"op": "replace", "path": ["registry", l[0], l[1]], "value": null}])
		r := data.stig.windows_server_2022.main.compliance_report with input as inp
		count(rd[l]) >= 1
		rd[l] - {f.stig_id | some f in r.open_findings} == set()
		r.compliant == false
	}
}
