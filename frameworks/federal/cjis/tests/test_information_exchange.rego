package cjis.information_exchange_test

import rego.v1

import data.cjis.information_exchange

all_attested := {"cjis": {"information_exchange": {"requirements": {
	"IEA-1": true,
	"IEA-2": true,
	"IEA-3": true,
	"IEA-4": true,
	"IEA-5": true,
	"IEA-6": true,
	"IEA-7": true,
}}}}

# Empty input: every requirement fires and the area is not compliant.
test_empty_input_all_violations if {
	count(information_exchange.violation) == count(information_exchange.requirements) with input as {}
	not information_exchange.area_compliant with input as {}
}

# All attested: no violations and the area is compliant.
test_all_attested_compliant if {
	count(information_exchange.violation) == 0 with input as all_attested
	information_exchange.area_compliant with input as all_attested
}

# Single flip: exactly one violation, naming its id.
test_single_flip_one_violation if {
	inp := json.remove(all_attested, ["cjis/information_exchange/requirements/IEA-3"])
	violations := information_exchange.violation with input as inp
	count(violations) == 1
	some msg in violations
	contains(msg, "IEA-3")
}

# compliance_report is populated on empty input.
test_compliance_report_populated if {
	report := information_exchange.compliance_report with input as {}
	report.policy_area == 1
	report.area_name == "Information Exchange Agreements"
	report.requirements_evaluated == count(information_exchange.requirements)
	report.violation_count == count(information_exchange.requirements)
	report.compliant == false
}
