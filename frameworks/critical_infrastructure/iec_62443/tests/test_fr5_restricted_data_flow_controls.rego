package iec_62443.fr5_test

import rego.v1

has(prefix, inp) if {
	v := data.iec_62443.fr5.violations with input as inp
	some x in v
	startswith(x, prefix)
}

net := {"it_ot_segmentation": true, "network_inventory_documented": true, "dmz_implemented": true, "wireless_policy_documented": true, "direct_internet_connectivity_to_ics": false}

test_absent_zones_flagged if {
	inp := {"target_sl": 2, "network": net}
	has("IEC 62443 SR 5.1 (RDF): No network zones defined", inp)
	has("IEC 62443 SR 5.1 RE 1 SL2 (RDF)", inp)
	not data.iec_62443.fr5.compliant with input as inp
}

test_zones_present_not_flagged if {
	inp := {"target_sl": 1, "network": net, "zones": [{"name": "a"}]}
	not has("IEC 62443 SR 5.1 (RDF): No network zones defined", inp)
}

conduit(src, dst) := {"source_zone": src, "dest_zone": dst, "firewall_or_dmz": true, "traffic_filtered": true, "encrypted": true}

test_default_named_it_ot_without_gateway_flagged if has("IEC 62443 SR 5.2 RE 1 SL3", {"target_sl": 3, "conduits": [conduit("corporate_it", "ics_control")]})

test_differently_named_it_ot_without_gateway_flagged if {
	has("IEC 62443 SR 5.2 RE 1 SL3", {"target_sl": 3, "conduits": [conduit("IT", "OT")]})
	has("IEC 62443 SR 5.2 RE 1 SL3", {"target_sl": 3, "conduits": [conduit("Corporate-IT", "SCADA")]})
}

test_typed_zones_flagged if {
	inp := {"target_sl": 3, "zones": [{"name": "zoneA", "type": "it"}, {"name": "zoneB", "type": "ot"}], "conduits": [conduit("zoneA", "zoneB")]}
	has("IEC 62443 SR 5.2 RE 1 SL3", inp)
}

test_gateway_present_not_flagged if {
	c := object.union(conduit("IT", "OT"), {"unidirectional_gateway": true})
	not has("IEC 62443 SR 5.2 RE 1 SL3", {"target_sl": 3, "conduits": [c]})
}

test_dmz_to_ot_not_flagged if not has("IEC 62443 SR 5.2 RE 1 SL3", {"target_sl": 3, "conduits": [conduit("dmz", "ot")]})
