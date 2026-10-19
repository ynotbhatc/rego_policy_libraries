package gdpr.data_transfers_test

import rego.v1

base := {"gdpr": {"transfers": {
	"general": {"adequacy_or_safeguards": {"in_place": true}, "onward_transfers": {"restricted": true}, "compliance_documented": true},
	"inventory": {"maintained": true, "all_third_country_flows": {"documented": true}, "mechanism_per_transfer": {"documented": true}, "regularly_reviewed": true},
	"transparency": {"privacy_notice": {"mentions_transfers": true}, "countries": {"identified": true}, "safeguards": {"mentioned": true}},
	"destination_countries": ["India"],
}}}

adequacy_flags := {"gdpr": {"transfers": {"adequacy": {"countries_verified": true, "list_current": true, "monitoring": {"for_withdrawal": true}}}}}

test_no_mechanism_at_all_is_not_compliant if {
	not data.gdpr.data_transfers.compliant with input as base
	not data.gdpr.data_transfers.transfer_mechanism_in_place with input as base
}

test_adequacy_flags_do_not_cover_non_adequate_destination if {
	i := object.union(base, adequacy_flags)
	not data.gdpr.data_transfers.adequacy_decision with input as i
}

test_adequacy_applies_for_adequate_destination if {
	i := object.union(object.union(base, adequacy_flags), {"gdpr": {"transfers": {"destination_countries": ["Japan", "Switzerland"]}}})
	data.gdpr.data_transfers.adequacy_decision with input as i
	data.gdpr.data_transfers.compliant with input as i
}

test_mixed_destinations_not_adequate if {
	i := object.union(object.union(base, adequacy_flags), {"gdpr": {"transfers": {"destination_countries": ["Japan", "India"]}}})
	not data.gdpr.data_transfers.adequacy_decision with input as i
}

test_united_states_needs_dpf_not_country_name if {
	i := object.union(object.union(base, adequacy_flags), {"gdpr": {"transfers": {"destination_countries": ["United States"]}}})
	not data.gdpr.data_transfers.adequacy_decision with input as i
}

test_us_dpf_certified_is_a_mechanism if {
	i := object.union(base, {"gdpr": {"transfers": {"us_transfers": {"occur": true, "mechanism": {"eu_us_dpf_or_scc": true}, "recipient": {"certified_or_scc_signed": true}, "dpf_certification": {"verified": true}}}}})
	data.gdpr.data_transfers.transfer_mechanism_in_place with input as i
}

test_documented_derogation_is_a_mechanism if {
	i := object.union(base, {"gdpr": {"transfers": {"derogations": {"used": true, "basis": {"documented": true, "explicit_consent": true}}}}})
	data.gdpr.data_transfers.transfer_mechanism_in_place with input as i
}

test_bcr_in_use_is_a_mechanism if {
	i := object.union(base, {"gdpr": {"transfers": {"bcr": {"used": true, "approved_by_lead_dpa": true, "legally_binding": true, "covers_all_entities": true, "enforceable_by_data_subjects": true, "published": true, "dpo_responsible": true}}}})
	data.gdpr.data_transfers.transfer_mechanism_in_place with input as i
}

test_absent_flags_are_not_applicability_declarations if {
	not data.gdpr.data_transfers.binding_corporate_rules with input as {}
	not data.gdpr.data_transfers.eu_us_dpf with input as {}
	not data.gdpr.data_transfers.derogation_if_used with input as {}
	not data.gdpr.data_transfers.supplementary_measures with input as {}
}

# decisions 2026-10-19: the SCC + TIA route requires supplementary measures when the TIA says so.
scc_tia := {"gdpr": {"transfers": {
	"scc": {"used": true, "eu_commission_approved_version": true, "signed_by_parties": true, "not_amended_invalidly": true, "transfer_impact_assessment": {"performed": true}},
	"tia": {"performed": true, "destination_country_laws": {"assessed": true}, "public_authority_access": {"assessed": true}, "documented": true, "supplementary_measures": {"identified_if_needed": true}},
}}}

measures := {"gdpr": {"transfers": {"supplementary_measures": {"technical": {"end_to_end_encryption": true, "pseudonymisation": true}, "contractual": {"additional_commitments": true}, "effective": true}}}}

test_scc_tia_with_required_but_missing_measures_is_not_a_mechanism if {
	i := object.union(object.union(base, scc_tia), {"gdpr": {"transfers": {"tia": {"supplementary_measures_required": true}}}})
	not data.gdpr.data_transfers.transfer_mechanism_in_place with input as i
	not data.gdpr.data_transfers.compliant with input as i
}

test_scc_tia_with_required_and_effective_measures_is_a_mechanism if {
	i := object.union(object.union(object.union(base, scc_tia), measures), {"gdpr": {"transfers": {"tia": {"supplementary_measures_required": true}}}})
	data.gdpr.data_transfers.transfer_mechanism_in_place with input as i
}

test_scc_tia_with_measures_not_required_is_a_mechanism if {
	i := object.union(object.union(base, scc_tia), {"gdpr": {"transfers": {"tia": {"supplementary_measures_required": false}}}})
	data.gdpr.data_transfers.transfer_mechanism_in_place with input as i
}

test_scc_tia_without_measures_declaration_fails_closed if {
	not data.gdpr.data_transfers.transfer_mechanism_in_place with input as object.union(base, scc_tia)
}
