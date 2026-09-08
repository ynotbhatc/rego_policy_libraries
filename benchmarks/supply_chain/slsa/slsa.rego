# SLSA v1.0 (build track) mapped onto the supply-chain substrate.
#
# The point of this file is the mapping, not new logic: SLSA's build-track
# levels are expressed entirely in terms of substrate rules the baseline and
# other frameworks also use. `reuses_substrate` names the shared rules — the
# overlap that makes the collapse visible.
#
#   L1  Provenance exists                 -> provenance present
#   L2  Signed by a hosted build platform -> substrate.provenance_ok + signing_ok
#   L3  Hardened, isolated builds         -> + substrate.build_hardening_ok
package supply_chain.slsa

import rego.v1

import data.supply_chain.substrate

build_l1 if input.provenance.present == true

build_l2 if {
	substrate.provenance_ok
	substrate.signing_ok
}

build_l3 if {
	build_l2
	substrate.build_hardening_ok
}

level := 3 if build_l3
else := 2 if build_l2
else := 1 if build_l1
else := 0

report := {
	"framework": "SLSA v1.0 (build track)",
	"build_level": level,
	"reuses_substrate": ["provenance", "signing", "build_hardening"],
}
