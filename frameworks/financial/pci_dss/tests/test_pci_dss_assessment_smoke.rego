# Contract smoke test for the CONSUMER-queried endpoint
# (/v1/data/pci_dss/pci_dss_assessment) — not the internal report rules.
package pci_dss_test

import rego.v1

import data.pci_dss

test_pci_dss_assessment_wellformed_on_empty_input if {
	a := pci_dss.pci_dss_assessment with input as {}
	is_object(a)
	is_boolean(a.compliant)
	is_number(a.score)
	is_object(a.requirement_results)
}
