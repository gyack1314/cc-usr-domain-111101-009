import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from datapack.pipeline import ERROR_LOG_NAME, MANIFEST_NAME, export_package, generate_key_file
from datapack.pseudonym import PseudonymError, Scope, TransformFailure
from datapack.storage import read_json

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
EXAMPLES = ROOT / "examples"

SECRET_NOTE = "合成内部备注"
SECRET_DISPLAY = "合成运营方A"


def _copy_samples(directory):
    bundle = Path(directory) / "bundle"
    shutil.copytree(SAMPLES, bundle)
    return bundle


def _scope(partner="P1", window="2026-W45", version="v1"):
    return Scope(partner, "traffic-data", window, version)


def _grep_tree(path, needle):
    for current, _dirs, files in os.walk(path):
        for name in files:
            target = Path(current) / name
            if target.is_file():
                try:
                    if needle.encode("utf-8") in target.read_bytes():
                        return str(target)
                except OSError:
                    continue
    return None


class ExportPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.bundle = _copy_samples(self.directory)
        self.key_file = self.directory / "private" / "keys.json"
        generate_key_file(self.key_file, ["v1", "v2"])
        self.policy = self.bundle / "policies.json"
        self.out = self.directory / "output" / "P1"

    def tearDown(self):
        self.temp.cleanup()

    def test_export_keeps_primary_and_foreign_integrity(self):
        manifest = export_package(self.bundle, self.policy, self.key_file, _scope(), self.out)
        self.assertEqual(manifest["scope"], _scope().as_dict())
        self.assertEqual(manifest["key_version"], "v1")
        vehicles = read_json(self.out / "vehicles.json")
        events = read_json(self.out / "events.json")
        operators = read_json(self.out / "operators.json")
        vehicle_ids = {row["vehicle_id"] for row in vehicles}
        self.assertEqual(len(vehicle_ids), len(vehicles))
        for event in events:
            self.assertIn(event["vehicle_ref"], vehicle_ids)
        operator_ids = {row["operator_id"] for row in operators}
        for vehicle in vehicles:
            self.assertIn(vehicle["operator_id"], operator_ids)
        for row in vehicles:
            self.assertIn(row["workshop"], ("W1", "W2"))
            self.assertNotIn("internal_note", row)
        self.assertNotIn("display", operators[0])
        on_disk = read_json(self.out / MANIFEST_NAME)
        manifest_columns = {item["table"]: item["columns"] for item in on_disk["tables"]}
        self.assertEqual(set(manifest_columns["vehicles"]), {"vehicle_id", "operator_id", "workshop"})
        self.assertNotIn("internal_note", manifest_columns["vehicles"])

    def test_partner_scopes_are_isolated(self):
        first = self.directory / "output" / "P1"
        second = self.directory / "output" / "P2"
        export_package(self.bundle, self.policy, self.key_file, _scope(partner="P1"), first)
        export_package(self.bundle, self.policy, self.key_file, _scope(partner="P2"), second)
        vehicles_p1 = read_json(first / "vehicles.json")
        vehicles_p2 = read_json(second / "vehicles.json")
        for left, right in zip(vehicles_p1, vehicles_p2):
            self.assertNotEqual(left["vehicle_id"], right["vehicle_id"])

    def test_key_rotation_builds_independent_immutable_copies(self):
        out_v1 = self.directory / "output" / "v1"
        out_v2 = self.directory / "output" / "v2"
        manifest_v1 = export_package(
            self.bundle, self.policy, self.key_file, _scope(version="v1"), out_v1
        )
        before = (out_v1 / "vehicles.json").read_bytes()
        manifest_v2 = export_package(
            self.bundle, self.policy, self.key_file, _scope(version="v2"), out_v2
        )
        self.assertEqual((out_v1 / "vehicles.json").read_bytes(), before)
        self.assertNotEqual(
            read_json(out_v1 / "vehicles.json")[0]["vehicle_id"],
            read_json(out_v2 / "vehicles.json")[0]["vehicle_id"],
        )
        self.assertEqual(manifest_v1["key_version"], "v1")
        self.assertEqual(manifest_v2["key_version"], "v2")
        for manifest in (manifest_v1, manifest_v2):
            self.assertNotIn("secret", json.dumps(manifest).lower())

    def test_existing_package_is_not_silently_overwritten(self):
        export_package(self.bundle, self.policy, self.key_file, _scope(), self.out)
        with self.assertRaises(PseudonymError) as context:
            export_package(self.bundle, self.policy, self.key_file, _scope(), self.out)
        self.assertEqual(context.exception.code, "PACKAGE_ALREADY_EXISTS")

    def test_same_package_cannot_mix_key_versions(self):
        export_package(self.bundle, self.policy, self.key_file, _scope(version="v1"), self.out)
        before = (self.out / "vehicles.json").read_bytes()
        with self.assertRaises(PseudonymError) as context:
            export_package(self.bundle, self.policy, self.key_file, _scope(version="v2"), self.out)
        self.assertEqual(context.exception.code, "PACKAGE_ALREADY_EXISTS")
        self.assertEqual((self.out / "vehicles.json").read_bytes(), before)
        manifest = read_json(self.out / MANIFEST_NAME)
        self.assertEqual(manifest["key_version"], "v1")

    def test_resume_without_journal_is_rejected(self):
        with self.assertRaises(PseudonymError) as context:
            export_package(
                self.bundle, self.policy, self.key_file, _scope(), self.out, resume=True
            )
        self.assertEqual(context.exception.code, "JOURNAL_NOT_FOUND")

    def test_scope_outside_policy_contract_is_rejected(self):
        with self.assertRaises(PseudonymError) as context:
            export_package(
                self.bundle,
                self.policy,
                self.key_file,
                _scope(window="2026-W46"),
                self.out,
            )
        self.assertEqual(context.exception.code, "SCOPE_NOT_ALLOWED")
        self.assertFalse(self.out.exists())

    def test_resume_rejects_foreign_scope_and_completes_same_scope(self):
        journal_out = self.directory / "output" / "resume"
        journal_path = journal_out / ".journal.json"

        class FirstTableFailure(Exception):
            pass

        from datapack import pipeline as pipeline_module

        original = pipeline_module._write_table
        attempts = {"count": 0}

        def flaky_write(path, rows, columns, suffix):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise FirstTableFailure("模拟中断")
            return original(path, rows, columns, suffix)

        pipeline_module._write_table = flaky_write
        try:
            with self.assertRaises(FirstTableFailure):
                export_package(self.bundle, self.policy, self.key_file, _scope(), journal_out)
        finally:
            pipeline_module._write_table = original
        self.assertTrue(journal_path.exists())
        with self.assertRaises(PseudonymError) as context:
            export_package(
                self.bundle,
                self.policy,
                self.key_file,
                _scope(partner="P2"),
                journal_out,
                resume=True,
            )
        self.assertEqual(context.exception.code, "JOURNAL_SCOPE_MISMATCH")
        manifest = export_package(
            self.bundle, self.policy, self.key_file, _scope(), journal_out, resume=True
        )
        self.assertFalse(journal_path.exists())
        self.assertTrue((journal_out / MANIFEST_NAME).exists())
        self.assertEqual(len(manifest["tables"]), 3)

    def test_failure_writes_error_log_without_raw_values_or_key_material(self):
        broken_bundle = self.directory / "broken"
        shutil.copytree(SAMPLES, broken_bundle)
        events_path = broken_bundle / "events.json"
        events = read_json(events_path)
        events[0]["vehicle_ref"] = "v-999"
        from datapack.storage import save_json

        save_json(events_path, events)
        with self.assertRaises(TransformFailure) as context:
            export_package(broken_bundle, self.policy, self.key_file, _scope(), self.out)
        self.assertEqual(len(context.exception.entries), 1)
        log_path = self.out / ERROR_LOG_NAME
        self.assertTrue(log_path.exists())
        log_text = log_path.read_text(encoding="utf-8")
        self.assertIn("REF_DANGLING", log_text)
        self.assertNotIn("v-999", log_text)
        self.assertFalse((self.out / "vehicles.json").exists())
        self.assertFalse((self.out / MANIFEST_NAME).exists())
        self.assertIsNone(_grep_tree(self.out, SECRET_NOTE))
        self.assertIsNone(_grep_tree(self.out, SECRET_DISPLAY))

    def test_collision_sample_blocks_delivery_under_short_pseudonyms(self):
        collision_bundle = self.directory / "collision"
        collision_bundle.mkdir()
        source = read_json(EXAMPLES / "collision-ids.json")
        from datapack.storage import save_json

        save_json(collision_bundle / "collisions.json", source)
        save_json(
            collision_bundle / "bundle.json",
            {
                "name": "碰撞样本",
                "files": [{"path": "collisions.json", "key": "id"}],
            },
        )
        policy_path = collision_bundle / "policy.json"
        save_json(
            policy_path,
            [
                {
                    "table": "collisions",
                    "primary": "id",
                    "pseudonym_length": 2,
                    "fields": {
                        "id": {"action": "id", "entity": "collision", "normalize": "exact"}
                    },
                }
            ],
        )
        with self.assertRaises(TransformFailure) as context:
            export_package(
                collision_bundle, policy_path, self.key_file, _scope(), self.out
            )
        self.assertIn(
            "PSEUDONYM_COLLISION", {entry["code"] for entry in context.exception.entries}
        )
        self.assertFalse((self.out / MANIFEST_NAME).exists())

    def test_keygen_refuses_overwrite_and_uses_private_mode(self):
        with self.assertRaises(PseudonymError) as context:
            generate_key_file(self.key_file, ["v3"])
        self.assertEqual(context.exception.code, "KEY_FILE_EXISTS")
        result = generate_key_file(self.key_file, ["v3"], force=True)
        self.assertEqual(result["mode"], "0600")
        if os.name == "posix":
            self.assertEqual(stat_mode(self.key_file) & 0o077, 0)
        content = read_json(self.key_file)
        self.assertTrue(content["keys"]["v3"]["secret"].startswith("base64:"))

    def test_success_leaves_no_error_log_or_pending_files(self):
        export_package(self.bundle, self.policy, self.key_file, _scope(), self.out)
        self.assertFalse((self.out / ERROR_LOG_NAME).exists())
        self.assertEqual(list(self.out.glob("**/.pending-*")), [])


def stat_mode(path):
    return path.stat().st_mode


class CliExportTests(unittest.TestCase):
    def test_cli_export_and_keygen_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = _copy_samples(root)
            key_file = root / "private" / "keys.json"
            out = root / "out"
            keygen = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "datapack.cli",
                    "keygen",
                    "--key-file",
                    str(key_file),
                    "--version",
                    "v1",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(keygen.returncode, 0, keygen.stderr)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "datapack.cli",
                    "export",
                    "--bundle",
                    str(bundle),
                    "--policy",
                    str(bundle / "policies.json"),
                    "--key-file",
                    str(key_file),
                    "--partner",
                    "P1",
                    "--project",
                    "traffic-data",
                    "--window",
                    "2026-W45",
                    "--key-version",
                    "v1",
                    "--out",
                    str(out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["scope"]["partner"], "P1")
            self.assertTrue((out / MANIFEST_NAME).exists())

    def test_cli_failure_exit_code_and_safe_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = _copy_samples(root)
            key_file = root / "keys.json"
            generate_key_file(key_file, ["v1"])
            events_path = bundle / "events.json"
            events = read_json(events_path)
            events[0]["vehicle_ref"] = "v-999"
            from datapack.storage import save_json

            save_json(events_path, events)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "datapack.cli",
                    "export",
                    "--bundle",
                    str(bundle),
                    "--policy",
                    str(bundle / "policies.json"),
                    "--key-file",
                    str(key_file),
                    "--partner",
                    "P1",
                    "--project",
                    "traffic-data",
                    "--window",
                    "2026-W45",
                    "--key-version",
                    "v1",
                    "--out",
                    str(root / "out"),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("v-999", result.stderr)
            self.assertIn("REF_DANGLING", result.stderr)


if __name__ == "__main__":
    unittest.main()
