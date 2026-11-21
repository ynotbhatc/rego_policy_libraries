package soc2.infrastructure.network_numeric_guards_test

import rego.v1

# "1" sorts above every number: a string zone count passed `>= 3`.
test_string_network_segmentation_compliant_is_false if {
	not data.soc2.infrastructure.network.network_segmentation_compliant with input as {"network": {"architecture": {"segmentation": {"enabled": true, "dmz": {"configured": true}, "internal_zones": {"count": "1"}, "zero_trust": {"enabled": true}}}}}
}

test_null_network_segmentation_compliant_is_false if {
	not data.soc2.infrastructure.network.network_segmentation_compliant with input as {"network": {"architecture": {"segmentation": {"enabled": true, "dmz": {"configured": true}, "internal_zones": {"count": null}, "zero_trust": {"enabled": true}}}}}
}

test_text_network_segmentation_compliant_is_false if {
	not data.soc2.infrastructure.network.network_segmentation_compliant with input as {"network": {"architecture": {"segmentation": {"enabled": true, "dmz": {"configured": true}, "internal_zones": {"count": "x"}, "zero_trust": {"enabled": true}}}}}
}

test_numeric_network_segmentation_compliant_unchanged if {
	data.soc2.infrastructure.network.network_segmentation_compliant with input as {"network": {"architecture": {"segmentation": {"enabled": true, "dmz": {"configured": true}, "internal_zones": {"count": 4}, "zero_trust": {"enabled": true}}}}}
}
