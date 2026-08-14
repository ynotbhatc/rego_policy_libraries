# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 2 -- Microsoft Defender
#
# NOTE ON PLACEMENT: SPF / DKIM / DMARC are section 2 controls in v7.0.0,
# not Exchange controls. The pre-v7 library evaluated them under its own
# "Exchange" module, which was one of the reasons its control numbers did
# not correspond to the benchmark.
#
# Input contract (from the aac.m365 collection):
#   input.exchange.verified_domains[] - {id, is_default, is_initial,
#                                        spf_present, dkim_present,
#                                        dmarc_present}
#
# NOT EVALUATED in this module: every Defender policy control (Safe Links,
# Safe Attachments, anti-phishing, anti-spam, connection filtering --
# 2.1.1 through 2.1.7 and 2.1.11 onward). The current collector returns
# only Microsoft Secure Score, which is a different control set from the
# CIS benchmark and cannot establish these controls. See COVERAGE.md.

package cis_m365_v7.defender

import rego.v1

default compliant := false

default facts_present := false

facts_present if {
	is_array(input.exchange.verified_domains)
}

# CIS 2.1.8 -- SPF records published for all Exchange domains.
violation contains msg if {
	some d in input.exchange.verified_domains
	not d.spf_present
	msg := sprintf("CIS 2.1.8: no SPF record published for domain '%s' -- receivers cannot distinguish legitimate senders from spoofed mail", [d.id])
}

# CIS 2.1.9 -- DKIM enabled for all Exchange Online domains.
violation contains msg if {
	some d in input.exchange.verified_domains
	not d.dkim_present
	msg := sprintf("CIS 2.1.9: DKIM not enabled for domain '%s' -- outbound mail carries no cryptographic origin signature", [d.id])
}

# CIS 2.1.10 -- DMARC records published for all Exchange Online domains.
violation contains msg if {
	some d in input.exchange.verified_domains
	not d.dmarc_present
	msg := sprintf("CIS 2.1.10: no DMARC record published for domain '%s' -- SPF and DKIM failures have no enforcement disposition", [d.id])
}

violation contains msg if {
	not facts_present
	msg := "CIS 2.1.8: verified-domain facts not collected -- SPF, DKIM and DMARC controls could not be evaluated (this is not a pass)"
}

compliant if {
	facts_present
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "2",
	"name": "Microsoft Defender",
	"section_total_controls": 21,
	"controls_evaluated": 3,
	"controls": ["2.1.8", "2.1.9", "2.1.10"],
	"facts_present": facts_present,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
