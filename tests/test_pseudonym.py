import hashlib
import hmac
import unittest

from datapack.pseudonym import (
    ALGORITHM,
    FULL_LENGTH,
    Engine,
    PseudonymError,
    Scope,
    TransformFailure,
    derive_pseudonym,
    encode_message,
    validate_policy,
)

KEY = b"0" * 32

POLICY = validate_policy(
    [
        {
            "table": "operators",
            "primary": "operator_id",
            "fields": {
                "operator_id": {"action": "id", "entity": "operator", "normalize": "exact"},
                "display": {"action": "drop"},
            },
        },
        {
            "table": "vehicles",
            "primary": "vehicle_id",
            "fields": {
                "vehicle_id": {"action": "id", "entity": "vehicle", "normalize": "upper_ascii"},
                "operator_id": {
                    "action": "ref",
                    "entity": "operator",
                    "normalize": "exact",
                    "ref_table": "operators",
                    "ref_field": "operator_id",
                },
                "workshop": {"action": "keep"},
                "internal_note": {"action": "drop"},
            },
        },
        {
            "table": "events",
            "primary": "event_id",
            "fields": {
                "event_id": {"action": "id", "entity": "event", "normalize": "exact"},
                "vehicle_ref": {
                    "action": "ref",
                    "entity": "vehicle",
                    "normalize": "upper_ascii",
                    "ref_table": "vehicles",
                    "ref_field": "vehicle_id",
                },
                "kind": {"action": "keep"},
            },
        },
    ]
)

TABLES = {
    "operators": [{"operator_id": "op-a", "display": "合成运营方A"}],
    "vehicles": [
        {"vehicle_id": "v-001", "operator_id": "op-a", "workshop": "W1", "internal_note": "备注一"},
        {"vehicle_id": "v-002", "operator_id": "op-a", "workshop": "W2", "internal_note": "备注二"},
    ],
    "events": [
        {"event_id": "e-1", "vehicle_ref": "v-001", "kind": "maintenance"},
        {"event_id": "e-2", "vehicle_ref": "V-002", "kind": "inspection"},
    ],
}


def make_scope(week="2026-W45", partner="P1", version="v1", project="traffic-data"):
    return Scope(partner, project, week, version)


class ScopedPseudonymTests(unittest.TestCase):
    def test_matches_standard_hmac_with_framed_message(self):
        scope = make_scope().for_entity("vehicle")
        message = encode_message(scope, "V-001")
        expected = hmac.new(KEY, message, hashlib.sha256).hexdigest()
        self.assertEqual(derive_pseudonym(KEY, scope, "V-001"), expected)
        self.assertEqual(len(derive_pseudonym(KEY, scope, "V-001")), FULL_LENGTH)

    def test_stable_within_scope(self):
        engine_a = Engine(_StaticKeyring(KEY), make_scope(), POLICY)
        engine_b = Engine(_StaticKeyring(KEY), make_scope(), POLICY)
        out_a = engine_a.run(TABLES)
        out_b = engine_b.run(TABLES)
        self.assertEqual(out_a, out_b)

    def test_scope_dimensions_isolate_pseudonyms(self):
        base_engine = Engine(_StaticKeyring(KEY), make_scope(), POLICY).run(TABLES)
        for overrides in ({"partner": "P2"}, {"week": "2026-W46"}, {"version": "v2"}, {"project": "other"}):
            kwargs = {"week": "2026-W45", "partner": "P1", "version": "v1"}
            kwargs.update(overrides)
            other = Engine(_StaticKeyring(KEY), make_scope(**kwargs), POLICY).run(TABLES)
            self.assertNotEqual(
                base_engine["vehicles"][0]["vehicle_id"],
                other["vehicles"][0]["vehicle_id"],
                overrides,
            )

    def test_entity_types_never_share_a_pseudonym_even_for_same_raw(self):
        policy = validate_policy(
            [
                {
                    "table": "a",
                    "primary": "a_id",
                    "fields": {"a_id": {"action": "id", "entity": "alpha", "normalize": "exact"}},
                },
                {
                    "table": "b",
                    "primary": "b_id",
                    "fields": {"b_id": {"action": "id", "entity": "beta", "normalize": "exact"}},
                },
            ]
        )
        data = {"a": [{"a_id": "same"}], "b": [{"b_id": "same"}]}
        out = Engine(_StaticKeyring(KEY), make_scope(), policy).run(data)
        self.assertNotEqual(out["a"][0]["a_id"], out["b"][0]["b_id"])

    def test_foreign_key_uses_same_pseudonym_and_case_is_normalized(self):
        out = Engine(_StaticKeyring(KEY), make_scope(), POLICY).run(TABLES)
        vehicle_pseudonyms = {row["vehicle_id"] for row in out["vehicles"]}
        for event in out["events"]:
            self.assertIn(event["vehicle_ref"], vehicle_pseudonyms)
        self.assertEqual(out["events"][1]["vehicle_ref"], out["vehicles"][1]["vehicle_id"])
        self.assertEqual(out["vehicles"][0]["operator_id"], out["operators"][0]["operator_id"])

    def test_dangling_reference_fails_delivery(self):
        broken = {name: [dict(row) for row in rows] for name, rows in TABLES.items()}
        broken["events"][0]["vehicle_ref"] = "v-999"
        failure = self._run_expecting_failure(broken)
        codes = {entry["code"] for entry in failure.entries}
        self.assertIn("REF_DANGLING", codes)
        entry = next(item for item in failure.entries if item["code"] == "REF_DANGLING")
        self.assertEqual(entry["table"], "events")
        self.assertEqual(entry["field"], "vehicle_ref")
        self.assertEqual(entry["row"], 1)
        self.assertNotIn("v-999", str(entry))

    def test_normalization_collision_is_rejected(self):
        broken = {name: [dict(row) for row in rows] for name, rows in TABLES.items()}
        broken["vehicles"].append(
            {"vehicle_id": "V-001", "operator_id": "op-a", "workshop": "W3", "internal_note": "x"}
        )
        failure = self._run_expecting_failure(broken)
        self.assertIn("NORMALIZATION_COLLISION", {entry["code"] for entry in failure.entries})
        self.assertNotIn("V-001", str(failure.entries))

    def test_undeclared_field_fails_delivery(self):
        broken = {name: [dict(row) for row in rows] for name, rows in TABLES.items()}
        broken["operators"][0]["secret_extra"] = "不应出现"
        failure = self._run_expecting_failure(broken)
        self.assertIn("ROW_FIELD_UNDECLARED", {entry["code"] for entry in failure.entries})
        self.assertNotIn("不应出现", str(failure.entries))

    def test_duplicate_primary_and_missing_value_are_reported(self):
        broken = {name: [dict(row) for row in rows] for name, rows in TABLES.items()}
        broken["vehicles"].append({"vehicle_id": "V-001", "operator_id": "op-a", "workshop": "W9"})
        broken["operators"].append({"operator_id": None, "display": "无主键"})
        failure = self._run_expecting_failure(broken)
        codes = {entry["code"] for entry in failure.entries}
        self.assertIn("PRIMARY_DUPLICATE", codes)
        self.assertIn("VALUE_MISSING", codes)

    def test_keep_values_pass_through_and_drop_fields_disappear(self):
        out = Engine(_StaticKeyring(KEY), make_scope(), POLICY).run(TABLES)
        self.assertEqual(out["vehicles"][0]["workshop"], "W1")
        self.assertNotIn("internal_note", out["vehicles"][0])
        self.assertNotIn("display", out["operators"][0])

    def test_short_pseudonym_collision_blocks_delivery(self):
        policy = validate_policy(
            [
                {
                    "table": "vehicles",
                    "primary": "vehicle_id",
                    "pseudonym_length": 2,
                    "fields": {
                        "vehicle_id": {
                            "action": "id",
                            "entity": "vehicle",
                            "normalize": "exact",
                        }
                    },
                }
            ]
        )
        data = {"vehicles": [{"vehicle_id": "V0000"}, {"vehicle_id": "V0001"}]}
        sequence = iter(("aa", "aa", "bb"))

        def stub_derive(key, entity_scope, normalized, length):
            return next(sequence)

        with self.assertRaises(TransformFailure) as context:
            Engine(_StaticKeyring(KEY), make_scope(), policy, derive=stub_derive).run(data)
        codes = {entry["code"] for entry in context.exception.entries}
        self.assertIn("PSEUDONYM_COLLISION", codes)
        self.assertNotIn("V0000", str(context.exception.entries))
        self.assertNotIn("V0001", str(context.exception.entries))

    def test_policy_rejects_bad_configuration(self):
        with self.assertRaises(PseudonymError) as context:
            validate_policy(
                [
                    {
                        "table": "vehicles",
                        "primary": "vehicle_id",
                        "fields": {
                            "vehicle_id": {"action": "id", "normalize": "exact"},
                        },
                    }
                ]
            )
        self.assertEqual(context.exception.code, "POLICY_ENTITY_MISSING")
        with self.assertRaises(PseudonymError):
            validate_policy([])
        conflicting = [
            {
                "table": "a",
                "primary": "a_id",
                "fields": {"a_id": {"action": "id", "entity": "x", "normalize": "exact"}},
            },
            {
                "table": "b",
                "primary": "b_id",
                "fields": {"b_id": {"action": "id", "entity": "x", "normalize": "strip"}},
            },
        ]
        with self.assertRaises(PseudonymError) as context:
            validate_policy(conflicting)
        self.assertEqual(context.exception.code, "POLICY_NORMALIZER_CONFLICT")

    def test_framing_distinguishes_scope_segmentation(self):
        scope = make_scope().for_entity("vehicle")
        self.assertNotEqual(
            encode_message(scope, "ab|c"),
            encode_message(scope, "a|bc"),
        )

    def test_scope_requires_all_dimensions(self):
        with self.assertRaises(PseudonymError):
            Scope("", "project", "2026-W45", "v1")
        with self.assertRaises(PseudonymError):
            Scope("P1", "project", "2026-W45", "")

    def test_policy_scope_whitelist(self):
        policy = validate_policy(
            {
                "scopes": [
                    {
                        "partner": "P1",
                        "project": "traffic-data",
                        "window": "2026-W45",
                        "key_version": "v1",
                    }
                ],
                "tables": [
                    {
                        "table": "vehicles",
                        "primary": "vehicle_id",
                        "fields": {
                            "vehicle_id": {
                                "action": "id",
                                "entity": "vehicle",
                                "normalize": "exact",
                            }
                        },
                    }
                ],
            }
        )
        from datapack.pseudonym import scope_allowed

        self.assertTrue(scope_allowed(policy, make_scope()))
        self.assertFalse(scope_allowed(policy, make_scope(week="2026-W46")))
        self.assertFalse(scope_allowed(policy, make_scope(partner="P2")))
        self.assertFalse(scope_allowed(policy, make_scope(version="v2")))
        self.assertTrue(scope_allowed(POLICY, make_scope(week="2099-W01")))
        with self.assertRaises(PseudonymError) as context:
            validate_policy(
                {
                    "scopes": [{"partner": "P1"}],
                    "tables": [
                        {
                            "table": "t",
                            "primary": "id",
                            "fields": {"id": {"action": "id", "entity": "x", "normalize": "exact"}},
                        }
                    ],
                }
            )
        self.assertEqual(context.exception.code, "POLICY_SCOPE_INVALID")

    def _run_expecting_failure(self, tables):
        with self.assertRaises(TransformFailure) as context:
            Engine(_StaticKeyring(KEY), make_scope(), POLICY).run(tables)
        return context.exception


class _StaticKeyring:
    def __init__(self, key):
        self._keys = {"v1": key, "v2": b"1" * 32}

    def key_for(self, version):
        try:
            return self._keys[version]
        except KeyError:
            raise PseudonymError("KEY_VERSION_UNKNOWN", field=version) from None

    def close(self):
        return None


if __name__ == "__main__":
    unittest.main()
