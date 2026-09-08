# The collapse, measured. Five independent supply-chain frameworks each map their
# requirements onto the shared substrate; this quantifies how many framework->theme
# references reduce to how few distinct themes — the supply-chain analogue of the
# original spine's "2,767 rules -> 65 controls -> 14 universal".
package supply_chain.metrics

import rego.v1

import data.supply_chain.s2c2f
import data.supply_chain.scrm_800_161
import data.supply_chain.slsa
import data.supply_chain.ssdf
import data.supply_chain.ssdf_genai
import data.supply_chain.substrate

frameworks := {
	"slsa": slsa.reuses_substrate,
	"ssdf": ssdf.reuses_substrate,
	"ssdf_genai": ssdf_genai.reuses_substrate,
	"scrm_800_161": scrm_800_161.reuses_substrate,
	"s2c2f": s2c2f.reuses_substrate,
}

# Total framework->theme reference edges (many).
framework_theme_references := sum([count(refs) | some _, refs in frameworks])

# Distinct substrate themes those references land on (few).
distinct_themes_referenced := count({t |
	some _, refs in frameworks
	some t in refs
})

collapse_report := {
	"frameworks": count(frameworks),
	"substrate_themes_total": count(substrate.themes),
	"framework_theme_references": framework_theme_references,
	"distinct_themes_referenced": distinct_themes_referenced,
	"note": "Independent frameworks' requirements reference a small shared substrate — the empirical collapse.",
}
