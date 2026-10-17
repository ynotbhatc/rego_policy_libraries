package cmmc_test

import rego.v1

all_true := [true, true, true, true, true, true, true, true, true, true, true, true, true, true]

test_failing_domain_flag_blocks_aggregate_even_with_no_violations if {
	not data.cmmc.compliant with data.cmmc.all_violations as []
	not data.cmmc.cmmc_level_2_compliant with data.cmmc.all_violations as []
}

test_all_domains_compliant_and_no_violations_is_compliant if {
	data.cmmc.compliant with data.cmmc.all_violations as [] with data.cmmc.domain_results as all_true
	data.cmmc.cmmc_level_2_compliant with data.cmmc.all_violations as [] with data.cmmc.domain_results as all_true
}

test_violations_still_block_when_domains_pass if {
	not data.cmmc.compliant with data.cmmc.all_violations as ["x"] with data.cmmc.domain_results as all_true
}
