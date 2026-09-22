#!/usr/bin/env python3
"""Offline v5/v4 -> v4/v3 registry conversion. Stop RDev before invoking this tool."""

import argparse
import datetime
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import uuid


SCHEMA_V3 = "rdev-device-registry.v3"
SCHEMA_V4 = "rdev-device-registry.v4"
SCHEMA_V5 = "rdev-device-registry.v5"
ROOT_FIELDS = {"schema", "devices", "enrollments"}
DEVICE_FIELDS = {
    "id", "owner_subject", "secret_hash", "credential_version", "created_at",
    "updated_at", "revoked_at",
}
ENROLLMENT_FIELDS = {
    "id", "subject", "code_hash", "created_at", "expires_at", "consumed_at",
    "revoked_at", "issued_device_id",
}


class RollbackError(Exception):
    """An error message that contains no registry values or credentials."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RollbackError("registry contains duplicate JSON fields")
        result[key] = value
    return result


def reject_constant(_value):
    raise RollbackError("registry contains a non-JSON numeric constant")


def prepare_registry(raw, target=SCHEMA_V3):
    if target not in (SCHEMA_V3, SCHEMA_V4):
        raise RollbackError("target must be v3 or v4")
    try:
        registry = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, UnicodeError):
        raise RollbackError("registry is not valid UTF-8 JSON") from None
    if not isinstance(registry, dict) or set(registry) != ROOT_FIELDS:
        raise RollbackError("registry top-level fields are not compatible with v3")
    schema = registry["schema"]
    if schema not in (SCHEMA_V3, SCHEMA_V4, SCHEMA_V5):
        raise RollbackError("only v3, v4 and v5 registries are supported")
    for field in ("devices", "enrollments"):
        if not isinstance(registry[field], list):
            raise RollbackError("registry record collections must be JSON arrays")
    ids = set()
    for device in registry["devices"]:
        if not isinstance(device, dict) or not set(device) <= DEVICE_FIELDS | {"maintenance_token"}:
            raise RollbackError("device fields are not compatible with v3")
        if not (DEVICE_FIELDS - {"revoked_at"}) <= set(device):
            raise RollbackError("device is missing required v3 fields")
        if not isinstance(device["id"], str) or not device["id"] or device["id"] in ids:
            raise RollbackError("registry contains invalid or duplicate device identities")
        ids.add(device["id"])
        if type(device["credential_version"]) is not int or not 0 < device["credential_version"] < 2**64:
            raise RollbackError("device credential version is invalid")
        if not all(isinstance(device[key], str) and device[key] for key in ("owner_subject", "secret_hash", "created_at", "updated_at")):
            raise RollbackError("device has invalid required v3 values")
        if schema == SCHEMA_V3 and "maintenance_token" in device:
            raise RollbackError("v3 registry unexpectedly contains maintenance authorization")
    for enrollment in registry["enrollments"]:
        if not isinstance(enrollment, dict) or not set(enrollment) <= ENROLLMENT_FIELDS:
            raise RollbackError("enrollment fields are not compatible with v3")
        if not {"id", "subject", "code_hash", "created_at", "expires_at"} <= set(enrollment):
            raise RollbackError("enrollment is missing required v3 fields")
        if not all(isinstance(value, str) for value in enrollment.values()):
            raise RollbackError("enrollment values are not compatible with v3")
        if enrollment["expires_at"] == "":
            if schema != SCHEMA_V5:
                raise RollbackError("legacy enrollment is missing its expiry")
            # Old versions require a future timestamp. Preserve usability on
            # rollback without restoring already consumed/revoked invitations.
            enrollment["expires_at"] = "9999-12-31T23:59:59Z"
    removed = 0
    if target == SCHEMA_V3:
        removed = sum("maintenance_token" in device for device in registry["devices"])
        for device in registry["devices"]:
            device.pop("maintenance_token", None)
        registry["schema"] = SCHEMA_V3
    elif schema == SCHEMA_V5:
        registry["schema"] = SCHEMA_V4
    converted = (json.dumps(registry, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return registry, converted, removed, schema != registry["schema"]


def read_snapshot(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RollbackError("registry must be a regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read()
        return raw, info
    finally:
        os.close(fd)


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_temp(directory, content, owner=None):
    fd, name = tempfile.mkstemp(prefix=".rdev-registry-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        if owner is not None:
            os.fchown(fd, owner.st_uid, owner.st_gid)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(fd)
    except BaseException:
        os.unlink(name)
        raise
    finally:
        os.close(fd)
    return Path(name)


def rollback_registry(path, target=SCHEMA_V3):
    if os.name != "posix":
        raise RollbackError("run this offline tool on the Linux RDev server or WSL")
    path = Path(os.path.abspath(path))
    if path.is_symlink():
        raise RollbackError("registry path must not be a symbolic link")
    raw, original_stat = read_snapshot(path)
    registry, converted, removed, changed = prepare_registry(raw, target)
    result = {"changed": changed, "registry": str(path), "schema": registry["schema"],
              "devices": len(registry["devices"]), "enrollments": len(registry["enrollments"]),
              "removed_maintenance_authorizations": removed}
    if not changed:
        return result
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    source_version = json.loads(raw)["schema"].rsplit(".", 1)[1]
    backup = path.with_name(path.name + "." + source_version + "-backup-" + stamp + "-" + uuid.uuid4().hex + ".json")
    temporary = private_temp(path.parent, raw)
    try:
        # Publishing a fully written inode is atomic and cannot overwrite a backup.
        os.link(temporary, backup)
        sync_directory(path.parent)
    finally:
        temporary.unlink()
    temporary = private_temp(path.parent, converted, original_stat)
    try:
        current, current_stat = read_snapshot(path)
        if current != raw or (current_stat.st_dev, current_stat.st_ino) != (original_stat.st_dev, original_stat.st_ino):
            raise RollbackError("registry changed during conversion; stop RDev before retrying")
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    result["backup"] = str(backup)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline RDev registry rollback. Stop RDev first. This tool never stops or starts services.")
    parser.add_argument("registry", help="exact managed_devices.json path on the stopped server")
    parser.add_argument("--target-schema", choices=("v3", "v4"), default="v3", help="v4 keeps fixed device tokens for feidu.19/20")
    args = parser.parse_args(argv)
    try:
        result = rollback_registry(args.registry, "rdev-device-registry." + args.target_schema)
    except RollbackError as error:
        print("registry rollback failed: " + str(error), file=sys.stderr)
        return 1
    except OSError:
        print("registry rollback failed during filesystem I/O; inspect the path and permissions", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
