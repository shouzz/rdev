import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TOOL = Path(__file__).with_name("maintenance-registry-rollback.py")
SPEC = importlib.util.spec_from_file_location("maintenance_registry_rollback", TOOL)
rollback = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rollback)


def fixture():
    def device(name, version):
        return {"id": name, "owner_subject": "feidu-user:42", "secret_hash": "test-secret-digest-" + name,
                "credential_version": version, "created_at": "2026-09-14T00:00:00Z", "updated_at": "2026-09-16T00:00:00Z"}
    original = device("original-device", 3)
    original["maintenance_token"] = {"tokenHash": "never-output-test-digest", "generation": 6, "revoked": True}
    added = device("device-added-after-upgrade", 1)
    revoked = device("device-revoked-after-upgrade", 5)
    revoked["revoked_at"] = "2026-09-16T00:00:00Z"
    return {"schema": rollback.SCHEMA_V4, "devices": [original, added, revoked], "enrollments": [
        {"id": "fixture-enrollment", "subject": "feidu-user:42", "code_hash": "never-output-enrollment-digest",
         "created_at": "2026-09-15T00:00:00Z", "expires_at": "2026-09-15T00:10:00Z", "consumed_at": "2026-09-15T00:01:00Z",
         "issued_device_id": added["id"]}]}


@unittest.skipUnless(os.name == "posix", "offline registry conversion targets Linux")
class RegistryRollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = Path(self.temp.name) / "managed_devices.json"
        self.original = fixture()
        self.original_bytes = (json.dumps(self.original, separators=(",", ":")) + "\n").encode()
        self.registry.write_bytes(self.original_bytes)

    def backups(self):
        return list(self.registry.parent.glob("*.v4-backup-*.json"))

    def test_preserves_current_devices_credentials_enrollment_and_revocation(self):
        result = rollback.rollback_registry(self.registry)
        converted = json.loads(self.registry.read_bytes())
        expected = copy.deepcopy(self.original)
        expected["schema"] = rollback.SCHEMA_V3
        for device in expected["devices"]:
            device.pop("maintenance_token", None)
        self.assertEqual(expected, converted)
        self.assertEqual(3, result["devices"])
        self.assertEqual(1, result["enrollments"])
        self.assertEqual(1, result["removed_maintenance_authorizations"])
        backup = Path(result["backup"])
        self.assertEqual(self.original_bytes, backup.read_bytes())
        self.assertEqual(0o600, backup.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.registry.stat().st_mode & 0o777)

    def test_v3_repeated_run_leaves_registry_and_backup_untouched(self):
        first = rollback.rollback_registry(self.registry)
        current = self.registry.read_bytes()
        backup = Path(first["backup"])
        backup_stat = backup.stat()
        second = rollback.rollback_registry(self.registry)
        self.assertFalse(second["changed"])
        self.assertNotIn("backup", second)
        self.assertEqual(current, self.registry.read_bytes())
        self.assertEqual([backup], self.backups())
        self.assertEqual(backup_stat.st_mtime_ns, backup.stat().st_mtime_ns)
        self.assertEqual(self.original_bytes, backup.read_bytes())

    def test_subsequent_upgrade_keeps_previous_backup_and_backs_up_latest_state(self):
        first = rollback.rollback_registry(self.registry)
        updated = fixture()
        updated["devices"][1]["credential_version"] = 9
        updated_bytes = json.dumps(updated).encode()
        self.registry.write_bytes(updated_bytes)
        second = rollback.rollback_registry(self.registry)
        self.assertNotEqual(first["backup"], second["backup"])
        self.assertEqual(self.original_bytes, Path(first["backup"]).read_bytes())
        self.assertEqual(updated_bytes, Path(second["backup"]).read_bytes())
        self.assertEqual(9, json.loads(self.registry.read_bytes())["devices"][1]["credential_version"])

    def test_invalid_or_future_input_never_changes_registry_or_creates_backup(self):
        future = fixture(); future["schema"] = "rdev-device-registry.v5"
        unknown = fixture(); unknown["devices"][0]["future_field"] = "unrepresentable"
        invalid_v3 = fixture(); invalid_v3["schema"] = rollback.SCHEMA_V3
        cases = [b'{"schema":"first","schema":"second"}', b'{"schema":NaN}', b'{"broken":',
                 json.dumps(future).encode(), json.dumps(unknown).encode(), json.dumps(invalid_v3).encode()]
        for raw in cases:
            with self.subTest(raw_length=len(raw)):
                self.registry.write_bytes(raw)
                with self.assertRaises(rollback.RollbackError):
                    rollback.rollback_registry(self.registry)
                self.assertEqual(raw, self.registry.read_bytes())
                self.assertEqual([], self.backups())

    def test_backup_publish_failure_leaves_registry_unchanged(self):
        with mock.patch.object(rollback.os, "link", side_effect=OSError("injected backup failure")):
            with self.assertRaises(OSError):
                rollback.rollback_registry(self.registry)
        self.assertEqual(self.original_bytes, self.registry.read_bytes())
        self.assertEqual([], self.backups())
        self.assertEqual([], list(self.registry.parent.glob(".rdev-registry-*")))

    def test_replace_failure_leaves_exact_backup_and_original(self):
        with mock.patch.object(rollback.os, "replace", side_effect=OSError("injected replace failure")):
            with self.assertRaises(OSError):
                rollback.rollback_registry(self.registry)
        self.assertEqual(self.original_bytes, self.registry.read_bytes())
        self.assertEqual(1, len(self.backups()))
        self.assertEqual(self.original_bytes, self.backups()[0].read_bytes())
        self.assertEqual([], list(self.registry.parent.glob(".rdev-registry-*")))

    def test_intervening_writer_is_not_overwritten(self):
        real_private_temp = rollback.private_temp
        changed = self.original_bytes + b" "
        def simulate_writer(directory, content, owner=None):
            result = real_private_temp(directory, content, owner)
            if owner is not None:
                self.registry.write_bytes(changed)
            return result
        with mock.patch.object(rollback, "private_temp", side_effect=simulate_writer):
            with self.assertRaises(rollback.RollbackError):
                rollback.rollback_registry(self.registry)
        self.assertEqual(changed, self.registry.read_bytes())
        self.assertEqual(self.original_bytes, self.backups()[0].read_bytes())

    def test_cli_prints_only_non_secret_summary(self):
        result = subprocess.run([sys.executable, str(TOOL), str(self.registry)], capture_output=True, check=True)
        summary = json.loads(result.stdout)
        self.assertTrue(summary["changed"])
        for value in [b"never-output", b"test-secret", b"secret_hash", b"tokenHash", b"code_hash"]:
            self.assertNotIn(value, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
