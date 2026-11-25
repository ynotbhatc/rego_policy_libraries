package tisax.missing_section_note_test

import rego.v1

# `not is_object(input.tisax)` is undefined when input.tisax is missing, so the "missing or not an object" note
# fired only for a present non-object.
test_missing_section_is_noted if {
	v := data.tisax.main.violations with input as {}
	"TISAX ISA2027 input: input.tisax is missing or not an object; no control can be evaluated" in v
}

test_non_object_section_is_noted if {
	v := data.tisax.main.violations with input as {"tisax": "yes"}
	"TISAX ISA2027 input: input.tisax is missing or not an object; no control can be evaluated" in v
}
