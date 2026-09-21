package essential_eight.office_macros

import rego.v1

# ACSC Essential Eight Maturity Model (Nov 2023) — Configure Microsoft Office Macro Settings.
# Requirements tagged by maturity level. Higher levels are cumulative over lower levels.
requirements := {
	# Maturity Level 1
	"OM-ML1-1": {"level": 1, "title": "Microsoft Office macros are disabled for users that do not have a demonstrated business requirement"},
	"OM-ML1-2": {"level": 1, "title": "Microsoft Office macros in files originating from the internet are blocked"},
	"OM-ML1-3": {"level": 1, "title": "Microsoft Office macro antivirus scanning is enabled"},
	"OM-ML1-4": {"level": 1, "title": "Microsoft Office macro security settings cannot be changed by users"},
	# Maturity Level 2 (adds to ML1)
	"OM-ML2-1": {"level": 2, "title": "Microsoft Office macros are blocked from making Win32 API calls"},
	"OM-ML2-2": {"level": 2, "title": "Allowed and blocked Microsoft Office macro execution events are logged"},
	# Maturity Level 3 (adds to ML2)
	"OM-ML3-1": {"level": 3, "title": "Microsoft Office macros are only allowed to execute in documents from Trusted Locations with limited write access, or if digitally signed by a trusted publisher"},
	"OM-ML3-2": {"level": 3, "title": "Microsoft Office's list of trusted publishers is validated on an annual or more frequent basis"},
	"OM-ML3-3": {"level": 3, "title": "Microsoft Office macros digitally signed by an untrusted publisher cannot be enabled via the Message Bar or Backstage View"},
	"OM-ML3-4": {"level": 3, "title": "Microsoft Office macros digitally signed by signatures other than V3 signatures cannot be enabled via the Message Bar or Backstage View"},
}

attested(id) if input.essential_eight.office_macros.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Essential Eight [Configure Microsoft Office Macro Settings] %s (ML%d): %s — not met", [id, m.level, m.title])
}

default strategy_compliant := false

strategy_compliant if count(violation) == 0

compliance_report := {
	"strategy": "Configure Microsoft Office Macro Settings",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": strategy_compliant,
}
