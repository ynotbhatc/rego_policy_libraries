#!/usr/bin/env python3
"""Unit tests for the logic of the checks themselves: the input-reference scan (scripts/input_refs.py), the
verdicts and mutations of scripts/check_bad_input_fails.py, and the registry / docs comparisons of
scripts/check_standard_releases.py.

    python3 -m unittest discover -s scripts/tests        (run by `make check-bad-input`)

The scan tests parse Rego with OPA ($OPA, else `opa` on PATH) and are skipped when there is none.
"""
import os, pathlib, shutil, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import check_bad_input_fails as bad  # noqa: E402
import check_standard_releases as std  # noqa: E402
import input_refs as ir  # noqa: E402

HAVE_OPA = shutil.which(os.environ.get("OPA", "opa")) is not None

MODULE = """
package t.main
import rego.v1
import data.t.lib

sys := input.system
cfg := object.get(input, "cfg", {})
CHECKS := {"c1": {"path": ["tab", "x"]}, "c2": {"path": ["tab", "y"]}}
IDS := {"AC-1", "AC-2"}

fact(p) := object.get(input, p, null)
section(n) := object.get(input, n, {})
flagged(o) if o.flag
outer(o) if flagged(o.inner)

v contains m if {
	some item in input.items
	not item.enc
	x := input.list[_]
	x.y == 1
	input.m[k].z
	object.get(input.q, "r", false) == false
	object.get(input, ["s", "t"], 1) > 0
	sys.name == "x"
	m := "x"
}
v contains "f" if flagged(input.zz)
v contains "e" if { every e in input.es { e.ok } }
v contains "c" if { some i, e in cfg.things; e.on; count([p | p := input.ps[_]; p.q]) > 0 }
v contains "g" if fact(["deep", "one"]) != true
v contains "h" if not section("iam").mfa
v contains id if { some id, c in CHECKS; object.get(input, c.path, null) != true }
v contains id if { some id in IDS; not input.controls[id].implemented }
v contains "o" if outer(input.wrap)
v contains "l" if not lib.ok
v contains "a" if not lib.acct.locked
"""

LIB = """
package t.lib
import rego.v1
acct := input.account
ok if input.lib_only.fact == true
"""

EXPECTED = {
    "account.locked", "cfg.things.[].on", "controls.AC-1.implemented", "controls.AC-2.implemented", "deep.one",
    "es.[].ok", "iam.mfa", "items.[].enc", "lib_only.fact", "list.[].y", "m.[].z", "ps.[].q", "q.r", "s.t",
    "system.name", "tab.x", "tab.y", "wrap.inner.flag", "zz.flag",
}


@unittest.skipUnless(HAVE_OPA, "no opa binary")
class ScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scan = ir.Scan(ir.parse_sources({"main.rego": MODULE, "lib.rego": LIB})).run()

    def test_every_kind_of_reference_is_found(self):
        got = {".".join(p) for p in ir.maximal(set().union(*self.scan.paths.values()))}
        self.assertEqual(got, EXPECTED)

    def test_closure_follows_the_packages_a_file_references(self):
        self.assertEqual(ir.closure(self.scan, ["main.rego"]), {"main.rego", "lib.rego"})
        self.assertEqual(ir.closure(self.scan, ["lib.rego"]), {"lib.rego"})

    def test_paths_are_attributed_to_the_file_that_reads_them(self):
        self.assertIn(("lib_only", "fact"), self.scan.paths["lib.rego"])
        self.assertNotIn(("lib_only", "fact"), self.scan.paths["main.rego"])
        # an alias defined in the library and read in main is main's reference
        self.assertIn(("account", "locked"), self.scan.paths["main.rego"])


class DocumentTest(unittest.TestCase):
    def test_leaves_lists_and_mixed_nodes(self):
        paths = [("a", "b"), ("a", "c"), ("items", ir.ANY, "x"), ("ports", ir.ANY), ("mix", "named"), ("mix", ir.ANY, "k")]
        self.assertEqual(ir.document(paths, "false"), {
            "a": {"b": "false", "c": "false"}, "items": [{"x": "false"}], "ports": ["false"],
            "mix": {"named": "false", "_any": {"k": "false"}}})
        self.assertEqual(ir.document([("a",)], None), {"a": None})
        self.assertEqual(ir.document([], "x"), {})

    def test_maximal_drops_prefixes(self):
        self.assertEqual(ir.maximal({("a",), ("a", "b"), ("a", "b", "c"), ("ab",), ("d",)}),
                         [("a", "b", "c"), ("ab",), ("d",)])

    def test_ref_cases(self):
        self.assertEqual(bad.ref_cases([]), [])
        cases = dict(bad.ref_cases([("a", "b")]))
        self.assertEqual(cases, {bad.CONTROL: {"a": {"b": False}}, "refs_str_false": {"a": {"b": "false"}},
                                 "refs_str_true": {"a": {"b": "true"}}, "refs_str_no": {"a": {"b": "no"}},
                                 "refs_null": {"a": {"b": None}}})


class VerdictTest(unittest.TestCase):
    def test_passes(self):
        self.assertTrue(bad.passes({"compliant": True, "violations": ["x"]}))
        self.assertTrue(bad.passes({"compliance_score": 100}))
        self.assertTrue(bad.passes({"violations": []}))
        self.assertFalse(bad.passes({"compliant": False, "violations": []}))
        self.assertFalse(bad.passes({"violations": ["x"]}))
        self.assertFalse(bad.passes(None))

    def test_findings(self):
        self.assertEqual(bad.findings({"violations": ["a", "b"], "failed_controls": 1}), (2, 1))
        self.assertEqual(bad.findings({"violation_count": 3}), (3, None))
        self.assertEqual(bad.findings({"violations": {"a": 1}, "failed": 4}), (1, 4))
        self.assertEqual(bad.findings({"failed_controls": True}), (None, None))
        self.assertEqual(bad.findings("x"), (None, None))

    def test_fewer(self):
        control = {"compliant": False, "violations": list(range(39))}
        self.assertIn("2 violations, 39", bad.fewer({"compliant": False, "violations": [1, 2]}, control))
        self.assertIsNone(bad.fewer({"violations": list(range(39))}, control))
        self.assertIsNone(bad.fewer({"violations": list(range(60))}, control))      # more findings is not a hole
        self.assertIn("1 failed controls, 5", bad.fewer({"failed_controls": 1}, {"failed_controls": 5}))
        self.assertIsNone(bad.fewer({"summary": "x"}, control))                      # nothing to compare


class FixtureCaseTest(unittest.TestCase):
    FX = {"mod": {"mfa": {"enabled": True, "root_login": False}, "days": 90, "flag": True, "unread": True}}
    SRC = "input.mod.mfa.enabled input.mod.mfa.root_login input.mod.days input.mod.flag"

    def setUp(self):
        self.cases = dict(bad.fixture_cases(self.FX, self.SRC))

    def test_every_boolean_leaf_gets_the_five_mutations(self):
        e = "mod.mfa.enabled"
        self.assertEqual(self.cases[f"boolstr:{e}"]["mod"]["mfa"]["enabled"], "true")
        self.assertEqual(self.cases[f"boolopp:{e}"]["mod"]["mfa"]["enabled"], "false")
        self.assertEqual(self.cases[f"boolno:{e}"]["mod"]["mfa"]["enabled"], "no")
        self.assertIsNone(self.cases[f"null:{e}"]["mod"]["mfa"]["enabled"])
        self.assertNotIn("enabled", self.cases[f"drop:{e}"]["mod"]["mfa"])
        r = "mod.mfa.root_login"
        self.assertEqual(self.cases[f"boolstr:{r}"]["mod"]["mfa"]["root_login"], "false")
        self.assertEqual(self.cases[f"boolopp:{r}"]["mod"]["mfa"]["root_login"], "true")

    def test_other_leaves_and_fields(self):
        self.assertEqual(self.cases["numstr:mod.days"]["mod"]["days"], "90")
        self.assertNotIn("mfa", self.cases["drop:mod.mfa"]["mod"])
        self.assertFalse(any("unread" in c for c in self.cases))       # the module never names it
        # a boolean that is itself a field: one drop: and one null: case, not two
        ids = [c for c, _ in bad.fixture_cases(self.FX, self.SRC)]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("drop:mod.flag", ids)
        self.assertIn("boolopp:mod.flag", ids)

    def test_the_fixture_is_not_changed(self):
        self.assertEqual(self.FX["mod"]["mfa"], {"enabled": True, "root_login": False})

    def test_sampling_is_stable_and_capped(self):
        fx = {"m": {f"k{i}": True for i in range(200)} | {"other": 1}}
        src = " ".join(f"k{i}" for i in range(200))
        a = [c for c, _ in bad.fixture_cases(fx, src) if c.startswith("boolopp:")]
        self.assertEqual(len(a), bad.LEAF_CAP)
        fx["m"]["k_new"] = True
        b = [c for c, _ in bad.fixture_cases(fx, src + " k_new") if c.startswith("boolopp:")]
        self.assertLessEqual(len(set(a) ^ set(b)), 2)                   # one leaf more moves at most one case


REGISTRY = """
| Framework / benchmark | Implemented version | Upstream owner |
|---|---|---|
| NERC CIP | per-standard — module cites {cip}. Upstream effective dates: CIP-003-9 2026-04-01 | NERC |
| Thing | **v1.2.0** (replaces the v1.1.0 file) | X |
| STIGs | RHEL 9 V2R10, Ubuntu V1R7 | DISA |
"""
REG = {"frameworks": {
    "nerc_cip": {"standards": [{"standard": "NERC CIP-003", "version": "CIP-003-9"}]},
    "thing": {"standards": [{"standard": "Thing", "version": "v1.2.0"}, {"standard": "Other", "version": "current"}]},
    "stig_rhel_9": {"standards": [{"standard": "RHEL 9 STIG", "version": "V2R10"}]},
    "stig_ubuntu": {"standards": [{"standard": "Ubuntu STIG", "version": "V1R7"}]}},
    "registry_rows": {"NERC CIP": ["nerc_cip"], "Thing": ["thing"], "STIGs": {"family": "stig_"}}}


class RegistryTest(unittest.TestCase):
    def test_a_stale_row_fails_even_when_the_new_version_is_quoted_as_upstream(self):
        errs = std.registry_errors(REG, REGISTRY.format(cip="CIP-003-8"))
        self.assertEqual(len(errs), 1)
        self.assertIn("CIP-003-9", errs[0])
        self.assertEqual(std.registry_errors(REG, REGISTRY.format(cip="CIP-003-9")), [])

    def test_rows_and_mapping_must_cover_each_other(self):
        reg = dict(REG, registry_rows={"NERC CIP": ["nerc_cip"], "Gone": [], "STIGs": {"family": "stig_"}})
        errs = std.registry_errors(reg, REGISTRY.format(cip="CIP-003-9"))
        self.assertTrue(any("'Gone' is not a row title" in e for e in errs))
        self.assertTrue(any("(Thing): row has no entry" in e for e in errs))

    def test_family_row_and_unknown_key(self):
        text = REGISTRY.format(cip="CIP-003-9").replace("V1R7", "V1R6")
        errs = std.registry_errors(REG, text)
        self.assertEqual(len(errs), 1)
        self.assertIn("V1R6", errs[0])
        reg = dict(REG, registry_rows=dict(REG["registry_rows"], Thing=["nope"]))
        self.assertTrue(any("'nope'" in e for e in std.registry_errors(reg, REGISTRY.format(cip="CIP-003-9"))))

    def test_version_matching(self):
        self.assertTrue(std.has_version("**v1.2.0** rebuilt", "v1.2.0"))
        self.assertTrue(std.has_version("r3 (2024-05-14) + r2 kept", "Rev 3"))
        self.assertTrue(std.has_version("Revision 3 of the guide", "Rev. 3"))
        self.assertFalse(std.has_version("2.0.1 is out", "2.0"))
        self.assertFalse(std.has_version("12.0", "2.0"))
        self.assertFalse(std.has_version("CIP-003-8", "CIP-003-9"))
        self.assertTrue(std.has_version("4.0.1 (sole active; v4.0 retired)", "v4.0.1"))


class DeclaredTotalTest(unittest.TestCase):
    def test_declared_totals(self):
        text = ('#     expected: 59\n_declared_controls := 153\nreport := {\n\t"total_requirements_evaluated": '
                '_declared_controls,\n\t"total_controls": max([_declared_controls, count(v)]), # see #324\n'
                '\t"total_checks": 12,\n}\nother := 7\n')
        self.assertEqual(std.declared_totals(text), {59, 153, 12})
        self.assertEqual(std.declared_totals('"total_controls": count(_all),'), set())

    def test_count_phrases(self):
        find = lambda s: std.DOC_RECS.findall(s)  # noqa: E731
        self.assertEqual(find("12 sections, 112 requirements"), [("112", "requirements")])
        self.assertEqual(find("All 1,014 controls and 352 recommendations"), [("1,014", "controls"), ("352", "recommendations")])
        self.assertEqual(find("424 SP 800-53 controls; the 110 Rev 2 requirements; v1.2 controls"), [])

    def test_states_count(self):
        self.assertTrue(std.states_count("# the 15 basic safeguarding requirements of (b)(1)", 15, "requirements"))
        self.assertFalse(std.states_count("# 153 violation rules", 112, "requirements"))
        self.assertFalse(std.states_count("# 1153 requirements", 153, "requirements"))


if __name__ == "__main__":
    unittest.main()
