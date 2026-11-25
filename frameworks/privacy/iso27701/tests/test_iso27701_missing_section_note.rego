package iso27701.missing_section_note_test

import rego.v1

# `not is_object(input.iso27701)` is undefined when input.iso27701 is missing, so the note fired only for a
# present non-object.
test_missing_section_is_noted if {
	v := data.iso27701.main.violations with input as {}
	"ISO 27701 input: input.iso27701 is missing or not an object; no control can be evaluated" in v
}

test_non_object_section_is_noted if {
	v := data.iso27701.main.violations with input as {"iso27701": []}
	"ISO 27701 input: input.iso27701 is missing or not an object; no control can be evaluated" in v
}
