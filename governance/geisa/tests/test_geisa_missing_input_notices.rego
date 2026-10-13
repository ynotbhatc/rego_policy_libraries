package governance.geisa.notices_test

import rego.v1

# `not is_object(input.x)` is undefined, not true, when x is missing; these notices must fire on {}.
test_adm_lwm2m_missing if {
	"ADM: lwm2m input missing or not an object" in data.governance.geisa.adm.violations with input as {}
}

test_lee_container_missing if {
	"LEE: container input missing or not an object" in data.governance.geisa.lee.violations with input as {}
}
