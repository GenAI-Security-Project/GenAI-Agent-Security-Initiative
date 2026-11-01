import copy
import unittest
from dataclasses import replace
from pathlib import Path

from main import (ASIS, Boundary, EffectPort, Invalid, Request, World, exercise,
                  load_documents, observe, permissive_adapter, protected_adapter,
                  validate, verify_observation, verify_suite)


class CrosswalkTests(unittest.TestCase):
    def setUp(self):
        self.crosswalk, self.document = load_documents()

    def test_exact_ten_category_and_requirement_coverage(self):
        self.assertEqual({row["asi"] for row in self.crosswalk["entries"]}, ASIS)
        self.assertEqual(len(self.crosswalk["requirements"]), 10)

    def test_unsupported_full_requirement_claims_are_explicit(self):
        for identifier in ("C9.2.6", "C9.2.7", "C9.2.9"):
            self.assertEqual(self.crosswalk["requirements"][identifier]["demonstration"],
                             "not_demonstrated")
        self.assertTrue(all(row["limitations"] for row in self.crosswalk["entries"]))

    def test_missing_and_duplicate_categories_rejected(self):
        for mutation in ("missing", "duplicate"):
            bad = copy.deepcopy(self.crosswalk)
            if mutation == "missing":
                bad["entries"].pop()
            else:
                bad["entries"][-1] = bad["entries"][0]
            with self.subTest(mutation=mutation), self.assertRaises(Invalid):
                validate(bad, self.document)

    def test_unknown_control_and_bad_level_rejected(self):
        for mutation in ("identifier", "level", "overclaim"):
            bad = copy.deepcopy(self.crosswalk)
            if mutation == "identifier":
                bad["entries"][0]["mappings"][0]["requirement"] = "C9.2.99"
            elif mutation == "level":
                bad["requirements"]["C9.2.8"]["level"] = 1
            else:
                bad["requirements"]["C9.2.9"]["demonstration"] = "boundary_subset"
            with self.subTest(mutation=mutation), self.assertRaises(Invalid):
                validate(bad, self.document)

    def test_edition_source_and_fixture_linkage_cannot_drift(self):
        for field, value in (("edition", "1.02-dev"), ("source_commit", "0" * 40),
                             ("source_url", "https://example.invalid")):
            bad = copy.deepcopy(self.crosswalk)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(Invalid):
                validate(bad, self.document)
        bad = copy.deepcopy(self.crosswalk)
        bad["entries"][0]["fixture"] = "unknown"
        with self.assertRaises(Invalid):
            validate(bad, self.document)

    def test_incident_analogues_have_honest_provenance(self):
        for fixture in self.document["fixtures"]:
            self.assertEqual(fixture["derivation"], "analogous")
            self.assertTrue(fixture["incident_basis"])
            self.assertIn(fixture["source"], self.document["sources"])

    def test_unsupported_attack_fields_and_boolean_budgets_rejected(self):
        for key, value in (("fanout", True), ("unknown", "payload")):
            bad = copy.deepcopy(self.document)
            bad["fixtures"][0]["attack"] = {key: value}
            with self.subTest(key=key), self.assertRaises(Invalid):
                validate(self.crosswalk, bad)

    def test_duplicate_fixture_id_and_mismatched_controls_rejected(self):
        bad = copy.deepcopy(self.document)
        bad["fixtures"][-1]["id"] = bad["fixtures"][0]["id"]
        with self.assertRaises(Invalid):
            validate(self.crosswalk, bad)
        bad = copy.deepcopy(self.document)
        bad["fixtures"][0]["controls"] = ["C9.2.1"]
        with self.assertRaises(Invalid):
            validate(self.crosswalk, bad)

    def test_file_loading_is_relative_to_module_not_working_directory(self):
        self.assertEqual(load_documents(Path(__file__).resolve().parent)[0]["edition"], "1.0")

    def test_malformed_document_shapes_and_boolean_versions_rejected(self):
        for value in ([], None, {"entries": None}):
            with self.subTest(value=value), self.assertRaises(Invalid):
                validate(value, self.document)
        bad = copy.deepcopy(self.crosswalk)
        bad["schema_version"] = True
        with self.assertRaises(Invalid):
            validate(bad, self.document)
        bad = copy.deepcopy(self.crosswalk)
        bad["requirements"]["C9.2.1"]["level"] = True
        with self.assertRaises(Invalid):
            validate(bad, self.document)

    def test_unknown_context_controls_and_duplicate_fixture_controls_rejected(self):
        bad = copy.deepcopy(self.crosswalk)
        bad["entries"][0]["additional_controls"] = ["C9.3.99"]
        with self.assertRaises(Invalid):
            validate(bad, self.document)
        bad = copy.deepcopy(self.document)
        bad["fixtures"][0]["controls"].append(bad["fixtures"][0]["controls"][0])
        with self.assertRaises(Invalid):
            validate(self.crosswalk, bad)


class NonFormationTests(unittest.TestCase):
    def setUp(self):
        _, document = load_documents()
        self.fixtures = document["fixtures"]

    def test_all_ten_negative_boundaries_prevent_formation(self):
        for fixture in self.fixtures:
            with self.subTest(asi=fixture["asi"]):
                result = exercise(fixture, negative=True)
                verify_observation(fixture, result, negative=True)
                self.assertFalse(result.formed)

    def test_all_ten_matched_positive_effects_are_reachable(self):
        for fixture in self.fixtures:
            with self.subTest(asi=fixture["asi"]):
                result = exercise(fixture, negative=False)
                verify_observation(fixture, result, negative=False)
                self.assertTrue(result.formed)

    def test_all_ten_permissive_negative_baselines_form(self):
        for fixture in self.fixtures:
            with self.subTest(asi=fixture["asi"]):
                result = exercise(fixture, negative=True, adapter=permissive_adapter)
                self.assertEqual((result.decision, result.formed), ("ALLOW", True))

    def test_leaky_denials_detected_independently(self):
        def leaky(boundary, request, port):
            port.write("leak")
            return "DENY"
        for fixture in self.fixtures:
            result = exercise(fixture, negative=True, adapter=leaky)
            self.assertEqual((result.decision, result.formed), ("DENY", True))
            with self.assertRaises(Invalid):
                verify_observation(fixture, result, negative=True)

    def test_dead_end_allows_do_not_pass_positive_controls(self):
        dead_end = lambda boundary, request, port: "ALLOW"
        for fixture in self.fixtures:
            result = exercise(fixture, negative=False, adapter=dead_end)
            self.assertEqual((result.decision, result.formed), ("ALLOW", False))
            with self.assertRaises(Invalid):
                verify_observation(fixture, result, negative=False)

    def test_harness_reaches_all_four_decision_effect_cells(self):
        fixture = self.fixtures[0]
        def leaky(boundary, request, port):
            port.write("leak")
            return "DENY"
        cases = [exercise(fixture, negative=True), exercise(fixture, negative=False),
                 exercise(fixture, negative=True, adapter=leaky),
                 exercise(fixture, negative=False, adapter=lambda b, r, p: "ALLOW")]
        self.assertEqual({(case.decision, case.formed) for case in cases},
                         {("DENY", False), ("ALLOW", True), ("DENY", True), ("ALLOW", False)})

    def test_alternate_surface_and_duplicate_effects_are_detected(self):
        def alternate(boundary, request, port):
            port.write("bypass", surface="shadow")
            return "ALLOW"
        def duplicate(boundary, request, port):
            port.write("one")
            port.write("two")
            return "ALLOW"
        fixture = self.fixtures[0]
        for adapter in (alternate, duplicate):
            with self.assertRaises(Invalid):
                verify_observation(fixture, exercise(fixture, negative=False, adapter=adapter),
                                   negative=False)

    def test_observer_detects_new_or_removed_surfaces_and_same_count_mutations(self):
        for before, after in [({"release": ()}, {"release": (), "new": ("leak",)}),
                              ({"release": ("old",)}, {"release": ("new",)}),
                              ({"release": ("old",)}, {})]:
            self.assertTrue(observe("DENY", before, after).formed)

    def test_adapter_errors_and_invalid_decisions_are_failures(self):
        def broken(boundary, request, port):
            raise RuntimeError("broken adapter")
        for adapter in (broken, lambda b, r, p: "UNKNOWN"):
            with self.assertRaises(Invalid):
                exercise(self.fixtures[0], negative=True, adapter=adapter)

    def test_worst_case_chain_and_fanout_checked_independently(self):
        request = Request(nonce="chain")
        boundary = Boundary("ASI08", request)
        self.assertTrue(boundary.allows(request))
        self.assertFalse(boundary.allows(replace(request, approval_grade=0)))
        self.assertFalse(boundary.allows(replace(request, fanout=5)))
        self.assertFalse(boundary.allows(replace(request, fanout=0)))

    def test_approval_identity_context_parameters_and_replay(self):
        request = Request(nonce="approval")
        boundary = Boundary("ASI09", request)
        world = World()
        port = EffectPort(world, "release")
        for changes in ({"actor": "other"}, {"target": "mock://other"},
                        {"goal": "release"}, {"parameters_json": "{}"}, {"epoch": 2}):
            self.assertFalse(boundary.allows(replace(request, **changes)))
        self.assertEqual(protected_adapter(boundary, request, port), "ALLOW")
        before = world.snapshot()
        self.assertEqual(protected_adapter(boundary, request, port), "DENY")
        self.assertEqual(before, world.snapshot())

    def test_expiry_and_live_revocation(self):
        request = Request(nonce="revocation")
        boundary = Boundary("ASI10", request)
        self.assertTrue(boundary.allows(request))
        boundary.revoked.add(request.actor)
        self.assertFalse(boundary.allows(request))
        other = Boundary("ASI09", request)
        other.now = request.expires_at
        self.assertFalse(other.allows(request))

    def test_dynamic_code_gadgets_are_never_admitted(self):
        request = Request(nonce="code")
        boundary = Boundary("ASI05", request)
        for code in ("eval('1')", "exec('pass')", "subprocess.run('echo')", "import os",
                     "().__class__", "add(1, 2 * 3)", "add(True,2)", "add(1,2);pass"):
            self.assertFalse(boundary.allows(replace(request, code=code)))

    def test_goal_labels_do_not_authorize_changed_targets_or_parameters(self):
        request = Request(nonce="goal")
        boundary = Boundary("ASI01", request)
        for changes in ({"target": "mock://other"},
                        {"parameters_json": '{"recipient":"other@example.invalid","text":"summary"}'}):
            self.assertFalse(boundary.allows(replace(request, **changes)))

    def test_child_grant_nonce_expiry_and_identity_bindings(self):
        request = Request(nonce="child")
        boundary = Boundary("ASI03", request)
        self.assertTrue(boundary.allows(request))
        for changes in ({"nonce": "fresh"}, {"expires_at": 1200}, {"actor": "other"}):
            self.assertFalse(boundary.allows(replace(request, **changes)))

    def test_nonfinite_expiry_boolean_grade_and_noncanonical_json_denied(self):
        request = Request(nonce="bad-input")
        boundary = Boundary("ASI02", request)
        for changes in ({"expires_at": float("nan")}, {"expires_at": float("inf")},
                        {"approval_grade": True}, {"fanout": True},
                        {"parameters_json": '{"recipient":"a","recipient":"b","text":"summary"}'}):
            self.assertFalse(boundary.allows(replace(request, **changes)))

    def test_suite_summary(self):
        result = verify_suite()
        self.assertEqual(result["protected_cases"], 20)
        self.assertEqual(result["permissive_reachability_cases"], 10)
        self.assertFalse(result["certification"])


if __name__ == "__main__":
    unittest.main()
