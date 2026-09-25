# Spine-coverage risk triage (basis of the evaluation-depth model, P28).
#
# Given an artifact's declared capabilities, compute its footprint on the
# invariant control substrate (which spine families its behavior implicates),
# score it by centrality-weighted coverage, and route it to an evaluation depth:
# little coverage -> light path; heavy coverage -> focused evaluation.
#
# The same triage applies to a dependency, a code change, or an AI-generated
# contribution — anything with a capability profile.
package supply_chain.coverage

import rego.v1

# Which spine control family each capability implicates.
capability_family := {
	"auth": "IA", "credentials": "IA",
	"access_control": "AC", "privileged": "AC",
	"crypto": "SC", "secrets": "SC", "data_at_rest": "SC",
	"audit": "AU", "logging": "AU",
	"config": "CM",
}

# Centrality weight per spine family (reuses the spine weighting).
family_weight := {"AC": 3, "AU": 3, "CM": 3, "IA": 3, "SC": 3}

# The artifact's spine footprint: the set of families it touches.
touched_families contains f if {
	some cap in input.artifact.capabilities
	f := capability_family[cap]
}

# Centrality-weighted coverage score.
score := sum([w |
	some f in touched_families
	w := family_weight[f]
])

# Evaluation depth from the score.
evaluation_depth := "focused" if score >= 6

evaluation_depth := "standard" if {
	score >= 3
	score < 6
}

evaluation_depth := "light" if score < 3

report := {
	"artifact": object.get(input.artifact, "name", "(unnamed)"),
	"touched_families": touched_families,
	"coverage_score": score,
	"evaluation_depth": evaluation_depth,
}
