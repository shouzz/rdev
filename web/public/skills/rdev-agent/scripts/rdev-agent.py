#!/usr/bin/env python3
"""Deterministic client for renewable Feidu RDev agent sessions."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import getpass
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


API_BASE = "https://pan.feidu.fit"
RDEV_BASE = "https://r.feidu.fit"
DRIVE_CLIENT_URL = "https://r.feidu.fit/tools/feidu-drive.py"
DRIVE_CLIENT_SHA256 = "d206720ca2269a24fbbc9c4d45a503795cb9a86ddcd4831e5422fb53cc7e7ea3"
CLAIM_RE = re.compile(r"^fdhc_[A-Za-z0-9_-]{43}$")
RENEWAL_RE = re.compile(r"^fdrn_[A-Za-z0-9_-]{43}$")
TICKET_RE = re.compile(r"^rdvat_[A-Za-z0-9_-]{43}$")
TERMINAL_TRANSFER_STATES = {"completed", "failed", "cancelled"}
WINDOWS_STATE_MAGIC = b"feidu.rdev-agent-state.dpapi.v1\x00"
LEASE_MAINTENANCE_INTERVAL_SECONDS = 60.0
PROCESS_TERMINATE_TIMEOUT_SECONDS = 5.0


class AgentError(RuntimeError):
    pass


class WindowsDataBlob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def windows_crypt(payload: bytes, protect: bool) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    description_type = ctypes.c_wchar_p if protect else ctypes.POINTER(ctypes.c_wchar_p)
    function.argtypes = [
        ctypes.POINTER(WindowsDataBlob), description_type,
        ctypes.POINTER(WindowsDataBlob), ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.POINTER(WindowsDataBlob),
    ]
    function.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    input_buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    input_blob = WindowsDataBlob(len(payload), input_buffer)
    output_blob = WindowsDataBlob()
    description = ctypes.c_wchar_p()
    if protect:
        succeeded = function(
            ctypes.byref(input_blob), None, None, None, None, 0x1,
            ctypes.byref(output_blob),
        )
    else:
        succeeded = function(
            ctypes.byref(input_blob), ctypes.byref(description), None, None, None,
            0x1, ctypes.byref(output_blob),
        )
    if not succeeded:
        raise AgentError(f"Windows DPAPI failed with error {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(output_blob.data, output_blob.size)
    finally:
        if output_blob.data:
            kernel32.LocalFree(output_blob.data)
        if description.value:
            kernel32.LocalFree(ctypes.cast(description, ctypes.c_void_p))


def default_state_path() -> pathlib.Path:
    if os.name == "nt":
        root = pathlib.Path(os.environ.get("LOCALAPPDATA", pathlib.Path.home() / "AppData" / "Local"))
    else:
        root = pathlib.Path(os.environ.get("XDG_CACHE_HOME", pathlib.Path.home() / ".cache"))
    return root / "Feidu" / "RDevAgent" / "current.json"


def validate_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise AgentError("service base URL must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AgentError("service base URL is invalid")
    return value.rstrip("/")


def canonical_uuid(value: str, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise AgentError(f"{field} is invalid") from error
    if str(parsed) != value:
        raise AgentError(f"{field} is invalid")
    return value


def parse_claim_deadline(value: str) -> int:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as error:
        raise AgentError("claim expiry is invalid") from error
    if parsed.tzinfo is None:
        raise AgentError("claim expiry must include a timezone")
    return int(parsed.timestamp() * 1000)


def request_json(base_url: str, method: str, path: str, payload=None, token: str = "") -> dict:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Accept": "application/json", "User-Agent": "feidu-rdev-agent/1"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(base_url + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 200:
                raise AgentError(f"service returned HTTP {response.status}")
            envelope = json.load(response)
    except urllib.error.HTTPError as error:
        raise AgentError(f"service returned HTTP {error.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise AgentError(f"service request failed: {type(error).__name__}") from None
    if not isinstance(envelope, dict) or envelope.get("code") != 0 or not isinstance(envelope.get("data"), dict):
        raise AgentError("service returned an invalid API envelope")
    return envelope["data"]


def fetch_config(rdev_base: str) -> int:
    request = urllib.request.Request(rdev_base + "/api/config", headers={"Accept": "application/json", "User-Agent": "feidu-rdev-agent/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 200:
                raise AgentError(f"RDev config returned HTTP {response.status}")
            data = json.load(response)
    except urllib.error.HTTPError as error:
        raise AgentError(f"RDev config returned HTTP {error.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise AgentError(f"RDev config request failed: {type(error).__name__}") from None
    port = data.get("sshPort")
    if not isinstance(port, str) or not port.isascii() or not port.isdigit():
        raise AgentError("RDev config returned an invalid sshPort")
    parsed = int(port)
    if str(parsed) != port or not 1 <= parsed <= 65535:
        raise AgentError("RDev config returned an invalid sshPort")
    return parsed


def write_state(path: pathlib.Path, state_data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.parent.chmod(0o700)
    payload = json.dumps(state_data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if os.name == "nt":
        payload = WINDOWS_STATE_MAGIC + windows_crypt(payload, True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if os.name != "nt":
                os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


@contextlib.contextmanager
def state_lock(path: pathlib.Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("a+b") as handle:
        if os.name != "nt":
            os.chmod(lock_path, 0o600)
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        else:
            import msvcrt
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            if os.name != "nt":
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def read_state(path: pathlib.Path) -> dict:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise AgentError("RDev agent session state is not a regular file")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600:
            raise AgentError("session state permissions must be 0600")
        payload = path.read_bytes()
        if os.name == "nt":
            if not payload.startswith(WINDOWS_STATE_MAGIC):
                raise AgentError("RDev agent session state is not DPAPI protected")
            payload = windows_crypt(payload[len(WINDOWS_STATE_MAGIC):], False)
        state_data = json.loads(payload.decode("utf-8"))
    except FileNotFoundError:
        raise AgentError("no active RDev agent session; run start first") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentError(f"cannot read RDev agent session: {type(error).__name__}") from None
    required = {
        "schema", "api_base", "rdev_base", "agent_session_id", "device_id", "renewal_token",
        "rdev_ticket", "developer_token", "ticket_expires_at_ms", "developer_token_expires_at_ms",
        "renewal_due_at_ms", "absolute_expires_at_ms", "minimum_safety_margin_seconds", "ssh_port",
    }
    if not isinstance(state_data, dict) or set(state_data) != required or state_data["schema"] != "feidu.rdev-agent-state.v1":
        raise AgentError("RDev agent session state is invalid")
    canonical_uuid(state_data["agent_session_id"], "agent_session_id")
    if not RENEWAL_RE.fullmatch(state_data["renewal_token"]):
        raise AgentError("RDev agent renewal token is invalid")
    if not TICKET_RE.fullmatch(state_data["rdev_ticket"]):
        raise AgentError("RDev access ticket is invalid")
    if not isinstance(state_data["developer_token"], str) or not state_data["developer_token"].startswith("fdpat_"):
        raise AgentError("Feidu developer token is invalid")
    return state_data


def session_path(state_data: dict, action: str) -> str:
    session_id = urllib.parse.quote(state_data["agent_session_id"], safe="")
    return f"/agent/v1/sessions/{session_id}/{action}" if action else f"/agent/v1/sessions/{session_id}"


def workload_payload(size_bytes: int, observed_bps: int) -> dict:
    if size_bytes < 0 or observed_bps < 0:
        raise AgentError("workload values must not be negative")
    return {"size_bytes": size_bytes, "observed_bytes_per_second": observed_bps}


def update_lease(state_data: dict, credentials: dict) -> None:
    session = credentials.get("agent_session")
    ticket = credentials.get("rdev_ticket")
    developer = credentials.get("developer_token")
    if not isinstance(session, dict) or not isinstance(ticket, dict) or not isinstance(developer, dict):
        raise AgentError("credential response is incomplete")
    if (
        session.get("agent_session_id") != state_data["agent_session_id"]
        or session.get("device_id") != state_data["device_id"]
        or credentials.get("device_id") != state_data["device_id"]
        or session.get("state") != "active"
    ):
        raise AgentError("credential response identity does not match the active session")
    renewal_token_present = "renewal_token" in session
    renewal_token = session.get("renewal_token")
    current_renewal_token = state_data.get("renewal_token", "")
    if current_renewal_token:
        if renewal_token_present and renewal_token != current_renewal_token:
            raise AgentError("credential response changed the stable renewal token")
        renewal_token = current_renewal_token
    elif not RENEWAL_RE.fullmatch(renewal_token or ""):
        raise AgentError("credential response did not include a valid renewal token")
    rdev_ticket = ticket.get("ticket")
    developer_token = developer.get("token")
    if not TICKET_RE.fullmatch(rdev_ticket or "") or not isinstance(developer_token, str) or not developer_token.startswith("fdpat_"):
        raise AgentError("credential response contains an invalid lease")
    state_data.update({
        "renewal_token": renewal_token,
        "rdev_ticket": rdev_ticket,
        "developer_token": developer_token,
        "ticket_expires_at_ms": ticket.get("expiresAtMs"),
        "developer_token_expires_at_ms": developer.get("expires_at_ms"),
        "renewal_due_at_ms": session.get("renewal_due_at_ms"),
        "absolute_expires_at_ms": session.get("absolute_expires_at_ms"),
        "minimum_safety_margin_seconds": session.get("minimum_safety_margin_seconds"),
    })
    for field in ("ticket_expires_at_ms", "developer_token_expires_at_ms", "renewal_due_at_ms", "absolute_expires_at_ms"):
        if not isinstance(state_data[field], int) or state_data[field] <= 0:
            raise AgentError(f"credential response contains an invalid {field}")
    if state_data["minimum_safety_margin_seconds"] != 600:
        raise AgentError("credential response contains an invalid minimum safety margin")


def update_renewed_session(state_data: dict, session: dict) -> None:
    if (
        not isinstance(session, dict)
        or session.get("agent_session_id") != state_data["agent_session_id"]
        or session.get("device_id") != state_data["device_id"]
        or session.get("state") != "active"
    ):
        raise AgentError("renew response identity does not match the active session")
    if "renewal_token" in session and session.get("renewal_token") != state_data["renewal_token"]:
        raise AgentError("renew response changed the stable renewal token")
    updates = {
        "ticket_expires_at_ms": session.get("ticket_expires_at_ms"),
        "developer_token_expires_at_ms": session.get("developer_token_expires_at_ms"),
        "renewal_due_at_ms": session.get("renewal_due_at_ms"),
        "absolute_expires_at_ms": session.get("absolute_expires_at_ms"),
        "minimum_safety_margin_seconds": session.get("minimum_safety_margin_seconds"),
    }
    for field in ("ticket_expires_at_ms", "developer_token_expires_at_ms", "renewal_due_at_ms", "absolute_expires_at_ms"):
        if not isinstance(updates[field], int) or updates[field] <= 0:
            raise AgentError(f"renew response contains an invalid {field}")
    if updates["minimum_safety_margin_seconds"] != 600:
        raise AgentError("renew response contains an invalid minimum safety margin")
    state_data.update(updates)


def renew(path: pathlib.Path, state_data: dict, size_bytes: int = 0, observed_bps: int = 0) -> dict:
    data = request_json(
        state_data["api_base"], "POST", session_path(state_data, "renew"),
        workload_payload(size_bytes, observed_bps), state_data["renewal_token"],
    )
    session = data.get("session")
    if not isinstance(session, dict):
        raise AgentError("renew response is incomplete")
    update_renewed_session(state_data, session)
    state_data["ssh_port"] = fetch_config(state_data["rdev_base"])
    write_state(path, state_data)
    return session


def heartbeat(state_data: dict, size_bytes: int = 0, observed_bps: int = 0) -> dict:
    data = request_json(
        state_data["api_base"], "POST", session_path(state_data, "heartbeat"),
        workload_payload(size_bytes, observed_bps), state_data["renewal_token"],
    )
    session = data.get("session")
    if not isinstance(session, dict) or session.get("agent_session_id") != state_data["agent_session_id"]:
        raise AgentError("heartbeat response is invalid")
    return session


def ensure_lease(path: pathlib.Path, state_data: dict, size_bytes: int = 0, observed_bps: int = 0) -> dict:
    now_ms = int(time.time() * 1000)
    estimated = 0 if not size_bytes or not observed_bps else (size_bytes + observed_bps - 1) // observed_bps
    margin_ms = (state_data["minimum_safety_margin_seconds"] + estimated) * 1000
    remaining_expiry = min(state_data["ticket_expires_at_ms"], state_data["developer_token_expires_at_ms"])
    if now_ms >= state_data["renewal_due_at_ms"] or now_ms + margin_ms >= remaining_expiry:
        return renew(path, state_data, size_bytes, observed_bps)
    session = heartbeat(state_data, size_bytes, observed_bps)
    state_data["ssh_port"] = fetch_config(state_data["rdev_base"])
    write_state(path, state_data)
    return session


def maintained_state(path: pathlib.Path, size_bytes: int = 0, observed_bps: int = 0, force_renew: bool = False):
    with state_lock(path):
        state_data = read_state(path)
        if force_renew:
            session = renew(path, state_data, size_bytes, observed_bps)
        else:
            session = ensure_lease(path, state_data, size_bytes, observed_bps)
        return state_data, session


def locked_state(path: pathlib.Path) -> dict:
    with state_lock(path):
        return read_state(path)


def safe_status(state_data: dict, session: dict) -> dict:
    return {
        "agent_session_id": state_data["agent_session_id"],
        "device_id": state_data["device_id"],
        "state": session.get("state"),
        "ssh_port": state_data["ssh_port"],
        "ticket_remaining_seconds": session.get("ticket_remaining_seconds"),
        "developer_token_remaining_seconds": session.get("developer_token_remaining_seconds"),
        "estimated_transfer_seconds": session.get("estimated_transfer_seconds"),
        "minimum_safety_margin_seconds": session.get("minimum_safety_margin_seconds"),
        "renewal_due_at_ms": session.get("renewal_due_at_ms"),
        "absolute_expires_at_ms": session.get("absolute_expires_at_ms"),
        "selected_transport": session.get("selected_transport"),
    }


def command_start(args) -> int:
    claim = getpass.getpass("Handoff claim: ") if sys.stdin.isatty() else sys.stdin.readline().strip()
    if not CLAIM_RE.fullmatch(claim):
        raise AgentError("handoff claim is invalid")
    deadline = parse_claim_deadline(args.claim_expires_at)
    if deadline <= int(time.time() * 1000):
        raise AgentError("handoff claim has expired")
    api_base = validate_base_url(args.api_base)
    rdev_base = validate_base_url(args.rdev_base)
    with state_lock(args.state):
        data = request_json(api_base, "POST", "/agent/v1/handoffs/redeem", {"claim": claim})
        claim = ""
        credentials = data.get("credentials")
        if not isinstance(credentials, dict) or credentials.get("device_id") != args.device:
            raise AgentError("handoff returned a different device identity")
        session = credentials.get("agent_session")
        if not isinstance(session, dict):
            raise AgentError("handoff did not return an agent session")
        session_id = canonical_uuid(session.get("agent_session_id", ""), "agent_session_id")
        state_data = {
            "schema": "feidu.rdev-agent-state.v1", "api_base": api_base, "rdev_base": rdev_base,
            "agent_session_id": session_id, "device_id": args.device, "renewal_token": "",
            "rdev_ticket": "", "developer_token": "", "ticket_expires_at_ms": 0,
            "developer_token_expires_at_ms": 0, "renewal_due_at_ms": 0,
            "absolute_expires_at_ms": 0, "minimum_safety_margin_seconds": 0,
            "ssh_port": fetch_config(rdev_base),
        }
        update_lease(state_data, credentials)
        write_state(args.state, state_data)
    print(json.dumps(safe_status(state_data, session), ensure_ascii=False))
    return 0


def command_status(args) -> int:
    state_data, session = maintained_state(args.state, args.size_bytes, args.observed_bytes_per_second)
    print(json.dumps(safe_status(state_data, session), ensure_ascii=False))
    return 0


def command_renew(args) -> int:
    state_data, session = maintained_state(args.state, args.size_bytes, args.observed_bytes_per_second, True)
    print(json.dumps(safe_status(state_data, session), ensure_ascii=False))
    return 0


def command_revoke(args) -> int:
    with state_lock(args.state):
        state_data = read_state(args.state)
        data = request_json(state_data["api_base"], "DELETE", session_path(state_data, ""), token=state_data["renewal_token"])
        session = data.get("session")
        if not isinstance(session, dict) or session.get("state") != "revoked":
            raise AgentError("revoke response is invalid")
        args.state.unlink(missing_ok=True)
    print(json.dumps({"agent_session_id": state_data["agent_session_id"], "state": "revoked"}))
    return 0


def askpass_environment(secret: str):
    temporary = tempfile.TemporaryDirectory(prefix="feidu-rdev-askpass-")
    root = pathlib.Path(temporary.name)
    if os.name == "nt":
        helper = root / "askpass.cmd"
        helper.write_text("@echo off\r\necho %RDEV_AGENT_SECRET%\r\n", encoding="ascii")
    else:
        helper = root / "askpass.sh"
        helper.write_text("#!/bin/sh\nprintf '%s\\n' \"$RDEV_AGENT_SECRET\"\n", encoding="ascii")
        helper.chmod(0o700)
    environment = os.environ.copy()
    environment.update({"SSH_ASKPASS": str(helper), "SSH_ASKPASS_REQUIRE": "force", "RDEV_AGENT_SECRET": secret, "DISPLAY": environment.get("DISPLAY", "feidu:0")})
    return temporary, environment


def terminate_subprocess(process) -> None:
    if process.poll() is not None:
        return
    with contextlib.suppress(OSError):
        process.terminate()
    try:
        process.wait(timeout=PROCESS_TERMINATE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            process.kill()
        process.wait()


def run_maintained_subprocess(state_path: pathlib.Path, command: list[str], environment: dict[str, str], size_bytes: int = 0, observed_bps: int = 0) -> int:
    try:
        process = subprocess.Popen(command, env=environment)
    except OSError as error:
        raise AgentError(f"cannot start child process: {type(error).__name__}") from None
    stopped = threading.Event()
    failures = []

    def maintain_lease() -> None:
        while not stopped.wait(LEASE_MAINTENANCE_INTERVAL_SECONDS):
            try:
                maintained_state(state_path, size_bytes, observed_bps)
            except Exception as error:
                failures.append(error)
                terminate_subprocess(process)
                return

    maintenance = threading.Thread(target=maintain_lease, name="rdev-agent-lease", daemon=True)
    maintenance.start()
    try:
        return_code = process.wait()
    except BaseException:
        terminate_subprocess(process)
        raise
    finally:
        stopped.set()
        maintenance.join()
    if failures:
        error = failures[0]
        if isinstance(error, AgentError):
            raise AgentError(f"lease maintenance failed while child process was running: {error}") from None
        raise AgentError(f"lease maintenance failed while child process was running: {type(error).__name__}") from None
    return return_code


def run_open_ssh(args, program: str, extra: list[str]) -> int:
    state_data, _ = maintained_state(args.state)
    executable = shutil.which(program)
    if not executable:
        raise AgentError(f"{program} is not installed")
    temporary, environment = askpass_environment(state_data["rdev_ticket"])
    common = ["-P" if program == "scp" else "-p", str(state_data["ssh_port"])]
    common += ["-o", "PasswordAuthentication=yes", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "StrictHostKeyChecking=accept-new"]
    try:
        return run_maintained_subprocess(args.state, [executable, *common, *extra], environment)
    finally:
        temporary.cleanup()


def command_ssh(args) -> int:
    state_data = locked_state(args.state)
    target = f"{state_data['device_id']}@{urllib.parse.urlsplit(state_data['rdev_base']).hostname}"
    command = args.remote_command
    if command and command[0] == "--":
        command = command[1:]
    return run_open_ssh(args, "ssh", [target, *command])


def command_scp_to(args) -> int:
    state_data = locked_state(args.state)
    target = f"{state_data['device_id']}@{urllib.parse.urlsplit(state_data['rdev_base']).hostname}:{args.remote_path}"
    return run_open_ssh(args, "scp", [args.local_path, target])


def command_scp_from(args) -> int:
    state_data = locked_state(args.state)
    source = f"{state_data['device_id']}@{urllib.parse.urlsplit(state_data['rdev_base']).hostname}:{args.remote_path}"
    return run_open_ssh(args, "scp", [source, args.local_path])


def cached_drive_client() -> pathlib.Path:
    path = default_state_path().parent / "tools" / "feidu-drive.py"
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == DRIVE_CLIENT_SHA256:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(DRIVE_CLIENT_URL, timeout=60) as response:
            payload = response.read(1024 * 1024)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise AgentError(f"cannot download Feidu drive client: {type(error).__name__}") from None
    if hashlib.sha256(payload).hexdigest() != DRIVE_CLIENT_SHA256:
        raise AgentError("Feidu drive client hash does not match this RDev Agent release")
    path.write_bytes(payload)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def command_drive(args) -> int:
    state_data, _ = maintained_state(args.state)
    environment = os.environ.copy()
    environment["FEIDU_DRIVE_TOKEN"] = state_data["developer_token"]
    return run_maintained_subprocess(args.state, [sys.executable, str(cached_drive_client()), *args.drive_args], environment)


def transfer_request(state_data: dict, method: str, transfer_id: str, action: str = "", payload=None) -> dict:
    canonical_uuid(transfer_id, "transfer_id")
    suffix = "/" + action if action else ""
    path = session_path(state_data, "transfers") + "/" + urllib.parse.quote(transfer_id, safe="") + suffix
    data = request_json(state_data["api_base"], method, path, payload, state_data["renewal_token"])
    transfer = data.get("transfer")
    if not isinstance(transfer, dict) or transfer.get("transfer_id") != transfer_id or transfer.get("agent_session_id") != state_data["agent_session_id"]:
        raise AgentError("cloud transfer response identity is invalid")
    return transfer


def command_transfer_create(args) -> int:
    state_data, _ = maintained_state(args.state, args.size_bytes, args.observed_bytes_per_second)
    transfer_id = args.transfer_id or str(uuid.uuid4())
    canonical_uuid(transfer_id, "transfer_id")
    payload = {
        "transfer_id": transfer_id, "direction": args.direction, "source_content_id": args.source_content_id,
        "source_path": args.source_path, "destination_parent_path": args.destination_parent_path,
        "file_name": args.file_name, "size_bytes": args.size_bytes,
    }
    path = session_path(state_data, "transfers")
    data = request_json(state_data["api_base"], "POST", path, payload, state_data["renewal_token"])
    transfer = data.get("transfer")
    if not isinstance(transfer, dict) or transfer.get("transfer_id") != transfer_id or transfer.get("agent_session_id") != state_data["agent_session_id"]:
        raise AgentError("cloud transfer response identity is invalid")
    if args.wait:
        return wait_for_transfer(args, transfer_id, transfer)
    print(json.dumps(transfer, ensure_ascii=False))
    return 0


def transfer_report_key(transfer: dict):
    status = transfer.get("status")
    size_bytes = transfer.get("size_bytes")
    bytes_done = transfer.get("bytes_done")
    if status in TERMINAL_TRANSFER_STATES:
        return status, bytes_done, transfer.get("error_message")
    if isinstance(size_bytes, int) and size_bytes > 0 and isinstance(bytes_done, int) and bytes_done >= 0:
        return status, min(20, bytes_done * 20 // size_bytes)
    return status, bytes_done


def wait_for_transfer(args, transfer_id: str, initial=None) -> int:
    transfer = initial
    last_report = None
    automatic_resumes = 0
    next_lease_check = 0.0
    while True:
        now = time.monotonic()
        if now >= next_lease_check:
            known_size = transfer.get("size_bytes", 0) if isinstance(transfer, dict) else 0
            state_data, _ = maintained_state(args.state, known_size if isinstance(known_size, int) else 0, args.observed_bytes_per_second)
            next_lease_check = now + 60
        else:
            state_data = locked_state(args.state)
        if transfer is None:
            transfer = transfer_request(state_data, "GET", transfer_id)
        report_key = transfer_report_key(transfer)
        if report_key != last_report:
            print(json.dumps(transfer, ensure_ascii=False), flush=True)
            last_report = report_key
        status = transfer.get("status")
        if status in TERMINAL_TRANSFER_STATES:
            if status == "failed" and automatic_resumes < args.auto_resume_attempts:
                automatic_resumes += 1
                transfer = transfer_request(state_data, "POST", transfer_id, "resume")
                print(json.dumps({
                    "transfer_id": transfer_id, "recovery_attempt": automatic_resumes,
                    "maximum_recovery_attempts": args.auto_resume_attempts, "status": transfer.get("status"),
                }, ensure_ascii=False), flush=True)
                last_report = None
                time.sleep(args.interval)
                continue
            return 1 if status in {"failed", "cancelled"} else 0
        time.sleep(args.interval)
        transfer = transfer_request(state_data, "GET", transfer_id)


def command_transfer_control(args) -> int:
    state_data, _ = maintained_state(args.state)
    if args.transfer_command == "status":
        transfer = transfer_request(state_data, "GET", args.transfer_id)
        if args.wait:
            return wait_for_transfer(args, args.transfer_id, transfer)
        print(json.dumps(transfer, ensure_ascii=False))
        return 1 if transfer.get("status") in {"failed", "cancelled"} else 0
    transfer = transfer_request(state_data, "POST", args.transfer_id, args.transfer_command)
    print(json.dumps(transfer, ensure_ascii=False))
    return 0


def command_maintain(args) -> int:
    while True:
        state_data, session = maintained_state(args.state)
        print(json.dumps(safe_status(state_data, session), ensure_ascii=False), flush=True)
        if session.get("state") != "active":
            return 0
        time.sleep(args.interval)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Renewable Feidu RDev agent session client")
    parser.add_argument("--state", type=pathlib.Path, default=default_state_path())
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start")
    start.add_argument("--device", required=True)
    start.add_argument("--claim-expires-at", required=True)
    start.add_argument("--api-base", default=API_BASE)
    start.add_argument("--rdev-base", default=RDEV_BASE)
    for name in ("status", "renew"):
        command = commands.add_parser(name)
        command.add_argument("--size-bytes", type=int, default=0)
        command.add_argument("--observed-bytes-per-second", type=int, default=0)
    commands.add_parser("revoke")
    ssh = commands.add_parser("ssh")
    ssh.add_argument("remote_command", nargs=argparse.REMAINDER)
    scp_to = commands.add_parser("scp-to")
    scp_to.add_argument("local_path")
    scp_to.add_argument("remote_path")
    scp_from = commands.add_parser("scp-from")
    scp_from.add_argument("remote_path")
    scp_from.add_argument("local_path")
    drive = commands.add_parser("drive")
    drive.add_argument("drive_args", nargs=argparse.REMAINDER)
    maintain = commands.add_parser("maintain")
    maintain.add_argument("--interval", type=int, default=60)
    transfer = commands.add_parser("transfer")
    transfer_commands = transfer.add_subparsers(dest="transfer_command", required=True)
    create = transfer_commands.add_parser("create")
    create.add_argument("--transfer-id", default="")
    create.add_argument("--direction", choices=("cloud_to_device", "device_to_cloud"), required=True)
    create.add_argument("--source-content-id", default="")
    create.add_argument("--source-path", default="")
    create.add_argument("--destination-parent-path", default="")
    create.add_argument("--file-name", required=True)
    create.add_argument("--size-bytes", type=int, required=True)
    create.add_argument("--observed-bytes-per-second", type=int, default=0)
    create.add_argument("--wait", action="store_true")
    create.add_argument("--interval", type=int, default=2)
    create.add_argument("--auto-resume-attempts", type=int, default=2)
    for name in ("status", "pause", "resume", "cancel"):
        command = transfer_commands.add_parser(name)
        command.add_argument("transfer_id")
        if name == "status":
            command.add_argument("--wait", action="store_true")
            command.add_argument("--interval", type=int, default=2)
            command.add_argument("--observed-bytes-per-second", type=int, default=0)
            command.add_argument("--auto-resume-attempts", type=int, default=2)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "interval", 1) <= 0:
        parser.error("--interval must be greater than zero")
    if getattr(args, "auto_resume_attempts", 0) < 0:
        parser.error("--auto-resume-attempts must not be negative")
    handlers = {
        "start": command_start, "status": command_status, "renew": command_renew, "revoke": command_revoke,
        "ssh": command_ssh, "scp-to": command_scp_to, "scp-from": command_scp_from,
        "drive": command_drive, "transfer": command_transfer_create if getattr(args, "transfer_command", "") == "create" else command_transfer_control,
        "maintain": command_maintain,
    }
    try:
        return handlers[args.command](args)
    except AgentError as error:
        print(f"rdev-agent: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
