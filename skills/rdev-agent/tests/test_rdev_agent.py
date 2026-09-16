from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "rdev-agent.py"
SPEC = importlib.util.spec_from_file_location("rdev_agent", SCRIPT)
rdev_agent = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(rdev_agent)


def envelope(data):
    return json.dumps({"code": 0, "message": "ok", "data": data}).encode()


class Handler(BaseHTTPRequestHandler):
    missing_token = object()
    renewal = "fdrn_" + "a" * 43
    renewal_response_token = missing_token
    ticket = "rdvat_" + "c" * 43
    renewed_ticket = "rdvat_" + "d" * 43
    session_id = "11111111-1111-4111-8111-111111111111"
    device_id = "DEVICE-EXACT"
    requests = []
    response_code = 0

    def log_message(self, *_):
        return

    def respond(self, data):
        payload = json.dumps({"code": self.response_code, "message": "test response", "data": data}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def session(self, renewal=missing_token):
        now = int(time.time() * 1000)
        value = {
            "agent_session_id": self.session_id, "device_id": self.device_id, "state": "active",
            "ticket_expires_at_ms": now + 28_800_000,
            "developer_token_expires_at_ms": now + 28_800_000,
            "ticket_remaining_seconds": 28800, "developer_token_remaining_seconds": 28800,
            "estimated_transfer_seconds": 0, "minimum_safety_margin_seconds": 600,
            "renewal_due_at_ms": now + 27_900_000, "absolute_expires_at_ms": now + 86_400_000,
            "selected_transport": "not_selected", "last_heartbeat_at_ms": now,
        }
        if renewal is not self.missing_token:
            value["renewal_token"] = renewal
        return value

    def credentials(self, renewal, ticket):
        now = int(time.time() * 1000)
        return {
            "handoff_id": "22222222-2222-4222-8222-222222222222", "device_id": self.device_id,
            "rdev_ticket": {"ticket": ticket, "ticketId": "ab" * 16, "deviceId": self.device_id, "expiresAtMs": now + 28_800_000},
            "developer_token": {"token": "fdpat_" + "e" * 43, "expires_at_ms": now + 28_800_000},
            "agent_session": self.session(renewal),
        }

    def do_GET(self):
        self.requests.append(("GET", self.path, self.headers.get("Authorization", "")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/unexpected-target")
            self.end_headers()
            return
        if self.path == "/api/config":
            payload = json.dumps({"sshPort": "18112"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        transfer = {"transfer_id": self.path.split("/")[-1], "device_id": self.device_id, "agent_session_id": self.session_id, "status": "completed"}
        self.respond({"items": []} if self.path == "/developer/v1/rdev/transfers" else {"transfer": transfer})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        self.requests.append(("POST", self.path, self.headers.get("Authorization", "")))
        if self.path == "/agent/v1/handoffs/redeem":
            self.respond({"credentials": self.credentials(self.renewal, self.ticket)})
        elif self.path.endswith("/renew"):
            self.respond({"session": self.session(self.renewal_response_token)})
        elif self.path.endswith("/heartbeat"):
            self.respond({"session": self.session()})
        elif self.path.endswith("/transfers"):
            self.respond({"transfer": {"transfer_id": body["transfer_id"], "device_id": self.device_id, "agent_session_id": self.session_id, "status": "queued"}})
        else:
            self.respond({"transfer": {"transfer_id": self.path.split("/")[-2], "device_id": self.device_id, "agent_session_id": self.session_id, "status": "paused"}})

    def do_DELETE(self):
        self.requests.append(("DELETE", self.path, self.headers.get("Authorization", "")))
        session = self.session()
        session["state"] = "revoked"
        self.respond({"session": session})


class ControlledProcess:
    def __init__(self):
        self.completed = threading.Event()
        self.returncode = None
        self.terminated = False
        self.killed = False

    def complete(self, returncode=0):
        self.returncode = returncode
        self.completed.set()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if not self.completed.wait(timeout):
            raise rdev_agent.subprocess.TimeoutExpired("controlled", timeout)
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.complete(143)

    def kill(self):
        self.killed = True
        self.complete(137)


class RDevAgentTest(unittest.TestCase):
    def setUp(self):
        Handler.requests = []
        Handler.renewal_response_token = Handler.missing_token
        Handler.response_code = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.temp = tempfile.TemporaryDirectory()
        self.state = pathlib.Path(self.temp.name) / "state.json"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.temp.cleanup()

    def run_main(self, args, stdin=""):
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), mock.patch.object(sys, "stdin", io.StringIO(stdin)):
            code = rdev_agent.main(["--state", str(self.state), *args])
        return code, output.getvalue(), errors.getvalue()

    def start(self):
        deadline = (rdev_agent.dt.datetime.now(rdev_agent.dt.timezone.utc) + rdev_agent.dt.timedelta(minutes=5)).isoformat()
        return self.run_main(["start", "--device", Handler.device_id, "--claim-expires-at", deadline, "--api-base", self.base, "--rdev-base", self.base], "fdhc_" + "z" * 43 + "\n")

    def test_start_status_renew_and_revoke_never_print_secrets(self):
        code, output, errors = self.start()
        self.assertEqual((code, errors), (0, ""))
        self.assertNotIn("fdhc_", output)
        self.assertNotIn("fdrn_", output)
        self.assertNotIn("rdvat_", output)
        state = rdev_agent.read_state(self.state)
        self.assertEqual(state["renewal_token"], Handler.renewal)
        if os.name == "nt":
            raw_state = self.state.read_bytes()
            self.assertTrue(raw_state.startswith(rdev_agent.WINDOWS_STATE_MAGIC))
            self.assertNotIn(Handler.renewal.encode(), raw_state)
            self.assertNotIn(Handler.ticket.encode(), raw_state)
        code, output, errors = self.run_main(["renew"])
        self.assertEqual((code, errors), (0, ""))
        state = rdev_agent.read_state(self.state)
        self.assertEqual(state["renewal_token"], Handler.renewal)
        self.assertEqual(state["rdev_ticket"], Handler.ticket)
        self.assertTrue(any(request[2] == "Bearer " + Handler.renewal for request in Handler.requests if request[1].endswith("/renew")))
        code, output, errors = self.run_main(["renew"])
        self.assertEqual((code, errors), (0, ""))
        renew_authorizations = [request[2] for request in Handler.requests if request[1].endswith("/renew")]
        self.assertEqual(renew_authorizations, ["Bearer " + Handler.renewal, "Bearer " + Handler.renewal])
        code, output, errors = self.run_main(["status", "--size-bytes", "104857601", "--observed-bytes-per-second", "1024"])
        self.assertEqual((code, errors), (0, ""))
        self.assertNotIn(Handler.renewal, output)
        code, output, errors = self.run_main(["revoke"])
        self.assertEqual((code, errors), (0, ""))
        self.assertFalse(self.state.exists())

    def test_renew_rejects_changed_stable_token_without_overwriting_state(self):
        code, _, errors = self.start()
        self.assertEqual((code, errors), (0, ""))
        original = self.state.read_bytes()
        Handler.renewal_response_token = "fdrn_" + "b" * 43
        code, _, errors = self.run_main(["renew"])
        self.assertEqual(code, 2)
        self.assertIn("changed the stable renewal token", errors)
        self.assertEqual(self.state.read_bytes(), original)

    def test_renew_rejects_explicit_null_stable_token_without_overwriting_state(self):
        code, _, errors = self.start()
        self.assertEqual((code, errors), (0, ""))
        original = self.state.read_bytes()
        Handler.renewal_response_token = None
        code, _, errors = self.run_main(["renew"])
        self.assertEqual(code, 2)
        self.assertIn("changed the stable renewal token", errors)
        self.assertEqual(self.state.read_bytes(), original)

    def test_invalid_utf8_state_returns_redacted_agent_error(self):
        if os.name == "nt":
            self.state.write_bytes(rdev_agent.WINDOWS_STATE_MAGIC + b"encrypted")
            patcher = mock.patch.object(rdev_agent, "windows_crypt", return_value=b"\xff")
        else:
            self.state.write_bytes(b"\xff")
            self.state.chmod(0o600)
            patcher = contextlib.nullcontext()
        with patcher, self.assertRaisesRegex(rdev_agent.AgentError, "cannot read RDev agent session: UnicodeDecodeError"):
            rdev_agent.read_state(self.state)

    def test_business_error_reports_only_integer_api_code(self):
        Handler.response_code = 503
        with self.assertRaisesRegex(rdev_agent.AgentError, r"^service returned API code 503$"):
            rdev_agent.request_json(
                self.base,
                "POST",
                f"/agent/v1/sessions/{Handler.session_id}/heartbeat",
                {"size_bytes": 0, "observed_bytes_per_second": 0},
                Handler.renewal,
            )

    def test_boolean_api_code_is_rejected_as_an_invalid_envelope(self):
        Handler.response_code = False
        with self.assertRaisesRegex(rdev_agent.AgentError, r"^service returned an invalid API envelope$"):
            rdev_agent.request_json(
                self.base,
                "POST",
                f"/agent/v1/sessions/{Handler.session_id}/heartbeat",
                {"size_bytes": 0, "observed_bytes_per_second": 0},
                Handler.renewal,
            )

    def test_start_rejects_mismatched_device_without_writing_state(self):
        deadline = (rdev_agent.dt.datetime.now(rdev_agent.dt.timezone.utc) + rdev_agent.dt.timedelta(minutes=5)).isoformat()
        code, _, errors = self.run_main(["start", "--device", "OTHER", "--claim-expires-at", deadline, "--api-base", self.base, "--rdev-base", self.base], "fdhc_" + "z" * 43 + "\n")
        self.assertEqual(code, 2)
        self.assertIn("different device identity", errors)
        self.assertFalse(self.state.exists())

    def test_transfer_wait_defaults_and_progress_reporting_are_bounded(self):
        transfer_id = "33333333-3333-4333-8333-333333333333"
        args = rdev_agent.build_parser().parse_args(["transfer", "status", transfer_id, "--wait"])
        self.assertEqual(args.auto_resume_attempts, 2)
        self.assertEqual(args.observed_bytes_per_second, 0)
        self.assertEqual(
            rdev_agent.transfer_report_key({"status": "running", "size_bytes": 1000, "bytes_done": 49}),
            ("running", 0),
        )
        self.assertEqual(
            rdev_agent.transfer_report_key({"status": "running", "size_bytes": 1000, "bytes_done": 50}),
            ("running", 1),
        )
        self.assertEqual(
            rdev_agent.transfer_report_key({"status": "failed", "bytes_done": 50, "error_message": "failed"}),
            ("failed", 50, "failed"),
        )

    def test_maintained_subprocess_keeps_running_across_successful_lease_maintenance(self):
        process = ControlledProcess()
        lease_calls = []

        def maintain(*args):
            lease_calls.append(args)
            process.complete(0)
            return {}, {}

        with (
            mock.patch.object(rdev_agent, "LEASE_MAINTENANCE_INTERVAL_SECONDS", 0.001),
            mock.patch.object(rdev_agent.subprocess, "Popen", return_value=process),
            mock.patch.object(rdev_agent, "maintained_state", side_effect=maintain),
        ):
            code = rdev_agent.run_maintained_subprocess(self.state, ["controlled"], {})
        self.assertEqual(code, 0)
        self.assertTrue(lease_calls)
        self.assertFalse(process.terminated)
        self.assertFalse(process.killed)

    def test_maintained_subprocess_fails_and_stops_child_when_lease_maintenance_fails(self):
        process = ControlledProcess()
        with (
            mock.patch.object(rdev_agent, "LEASE_MAINTENANCE_INTERVAL_SECONDS", 0.001),
            mock.patch.object(rdev_agent.subprocess, "Popen", return_value=process),
            mock.patch.object(rdev_agent, "maintained_state", side_effect=rdev_agent.AgentError("renew denied")),
        ):
            with self.assertRaisesRegex(rdev_agent.AgentError, "lease maintenance failed.*renew denied"):
                rdev_agent.run_maintained_subprocess(self.state, ["controlled"], {})
        self.assertTrue(process.terminated)
        self.assertFalse(process.killed)

    def test_scp_forces_legacy_protocol_before_connection_options(self):
        state = {"rdev_ticket": Handler.ticket, "ssh_port": 18112}
        temporary = mock.Mock()
        environment = {"SSH_ASKPASS_REQUIRE": "force"}
        args = mock.Mock(state=self.state)
        with (
            mock.patch.object(rdev_agent, "maintained_state", return_value=(state, {})),
            mock.patch.object(rdev_agent.shutil, "which", return_value="scp.exe"),
            mock.patch.object(rdev_agent, "askpass_environment", return_value=(temporary, environment)),
            mock.patch.object(rdev_agent, "run_maintained_subprocess", return_value=0) as run,
        ):
            code = rdev_agent.run_open_ssh(args, "scp", ["local.bin", "DEVICE-EXACT@example.test:remote.bin"])

        self.assertEqual(code, 0)
        run.assert_called_once_with(
            self.state,
            [
                "scp.exe", "-P", "18112",
                "-o", "PasswordAuthentication=yes",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                "local.bin", "DEVICE-EXACT@example.test:remote.bin",
            ],
            environment,
        )
        temporary.cleanup.assert_called_once_with()

    def test_ssh_places_forwarding_options_before_the_device_target(self):
        args = rdev_agent.build_parser().parse_args([
            "--state", str(self.state), "ssh",
            "--local-forward", "127.0.0.1:19080:127.0.0.1:19081",
            "--remote-forward", "127.0.0.1:19082:127.0.0.1:19083",
            "--no-command",
        ])
        state = {"device_id": Handler.device_id, "rdev_base": "https://r.feidu.fit"}
        with (
            mock.patch.object(rdev_agent, "locked_state", return_value=state),
            mock.patch.object(rdev_agent, "run_open_ssh", return_value=0) as run,
        ):
            code = rdev_agent.command_ssh(args)

        self.assertEqual(code, 0)
        run.assert_called_once_with(
            args,
            "ssh",
            [
                "-o", "ExitOnForwardFailure=yes",
                "-L", "127.0.0.1:19080:127.0.0.1:19081",
                "-R", "127.0.0.1:19082:127.0.0.1:19083",
                "-N", "DEVICE-EXACT@r.feidu.fit",
            ],
        )

    def test_ssh_rejects_no_command_with_remote_command(self):
        args = rdev_agent.build_parser().parse_args([
            "--state", str(self.state), "ssh", "--no-command", "--", "hostname",
        ])
        state = {"device_id": Handler.device_id, "rdev_base": "https://r.feidu.fit"}
        with mock.patch.object(rdev_agent, "locked_state", return_value=state):
            with self.assertRaisesRegex(rdev_agent.AgentError, "cannot be combined"):
                rdev_agent.command_ssh(args)

    def test_wait_for_cancelled_transfer_returns_nonzero(self):
        transfer_id = "33333333-3333-4333-8333-333333333333"
        args = rdev_agent.build_parser().parse_args(["transfer", "status", transfer_id, "--wait"])
        transfer = {"transfer_id": transfer_id, "agent_session_id": Handler.session_id, "status": "cancelled"}
        with mock.patch.object(rdev_agent, "maintained_state", return_value=({}, {})):
            self.assertEqual(rdev_agent.wait_for_transfer(args, transfer_id, transfer), 1)

    def test_cancelled_transfer_status_returns_nonzero_without_waiting(self):
        transfer_id = "33333333-3333-4333-8333-333333333333"
        args = rdev_agent.build_parser().parse_args(["transfer", "status", transfer_id])
        transfer = {"transfer_id": transfer_id, "agent_session_id": Handler.session_id, "status": "cancelled"}
        with (
            mock.patch.object(rdev_agent, "maintained_state", return_value=({}, {})),
            mock.patch.object(rdev_agent, "transfer_request", return_value=transfer),
        ):
            self.assertEqual(rdev_agent.command_transfer_control(args), 1)


class PermanentAccessTest(unittest.TestCase):
    """Exercise import and protocol boundaries with a local HTTP service."""

    setUp = RDevAgentTest.setUp
    tearDown = RDevAgentTest.tearDown
    run_main = RDevAgentTest.run_main

    def access(self, device=None):
        return {
            "schema": "rdev-device-access.v1", "device_id": device or Handler.device_id,
            "rdev_base": self.base, "api_base": self.base, "ssh_host": "127.0.0.1",
            "ssh_port": 18112, "token": "fdpat_" + "p" * 43,
        }

    def save_access(self):
        data = self.access()
        code, output, errors = self.run_main(["--import-stdin"], json.dumps(data))
        self.assertEqual((code, errors), (0, ""))
        self.assertNotIn(data["token"], output)
        return data

    def test_fixed_import_reuse_has_no_http_or_expiry_dependency(self):
        access = self.save_access()
        before = self.state.read_bytes()
        for action in ("status", "renew", "maintain"):
            code, output, errors = self.run_main([action])
            self.assertEqual((code, errors), (0, ""))
            self.assertEqual(json.loads(output)["authentication"], "permanent")
            self.assertNotIn(access["token"], output)
        self.assertEqual(Handler.requests, [])
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(rdev_agent.read_state(self.state), access)
        if os.name == "nt":
            self.assertTrue(before.startswith(rdev_agent.WINDOWS_STATE_MAGIC))
            self.assertNotIn(access["token"].encode(), before)
        else:
            self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)

    def test_import_exact_schema_and_explicit_replacement(self):
        data = self.save_access()
        data["token"] = "fdpat_" + "n" * 43
        code, output, errors = self.run_main(["--import-stdin"], json.dumps(data))
        self.assertEqual(code, 2)
        self.assertIn("--replace", errors)
        self.assertNotIn(data["token"], output + errors)
        code, _, errors = self.run_main(["--import-stdin", "--replace"], json.dumps(data))
        self.assertEqual((code, errors), (0, ""))
        data["claim"] = "not allowed"
        code, _, _ = self.run_main(["--import-stdin", "--replace"], json.dumps(data))
        self.assertEqual(code, 2)

    def test_clipboard_import_clears_only_successful_input_without_output(self):
        data = self.access()
        raw = json.dumps(data)
        with mock.patch.object(rdev_agent, "windows_clipboard", return_value=raw) as clipboard:
            code, output, errors = self.run_main(["--import-clipboard"])
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(clipboard.call_args_list, [mock.call(), mock.call(expected=raw)])
        self.assertNotIn(data["token"], output)

    def test_exact_device_lookup_across_new_invocations(self):
        with mock.patch.object(rdev_agent, "default_state_path", return_value=pathlib.Path(self.temp.name) / "current.json"):
            for device in ("ONE", "TWO"):
                access = self.access(device)
                with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(access))), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(rdev_agent.main(["--import-stdin"]), 0)
            args = rdev_agent.build_parser().parse_args(["--device", "ONE", "ssh", "--", "hostname"])
            self.assertEqual(rdev_agent.read_state(rdev_agent.resolve_state(args))["device_id"], "ONE")
            args = rdev_agent.build_parser().parse_args(["status"])
            with self.assertRaisesRegex(rdev_agent.AgentError, "multiple devices"):
                rdev_agent.resolve_state(args)

    def test_fixed_ssh_uses_one_token_without_lease_thread_or_replay(self):
        data = self.save_access()
        before = self.state.read_bytes()
        process = mock.Mock()
        process.wait.return_value = 255
        with mock.patch.object(rdev_agent.subprocess, "Popen", return_value=process) as popen, mock.patch.object(rdev_agent.shutil, "which", return_value="ssh"), mock.patch.object(rdev_agent, "run_maintained_subprocess", side_effect=AssertionError("lease path")):
            code, _, errors = self.run_main(["ssh", "--", "hostname"])
        self.assertEqual((code, errors), (255, ""))
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(process.wait.call_args, mock.call())  # no short command deadline
        command = popen.call_args.args[0]
        self.assertIn("ConnectTimeout=10", command)
        self.assertIn("ServerAliveInterval=15", command)
        self.assertIn("ServerAliveCountMax=3", command)
        self.assertIn("DEVICE-EXACT@127.0.0.1", command)
        self.assertNotIn(data["token"], " ".join(command))
        self.assertEqual(popen.call_args.kwargs["env"]["RDEV_AGENT_SECRET"], data["token"])
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(Handler.requests, [])

    def test_sftp_batch_and_drive_use_saved_service_and_credential(self):
        data = self.save_access()
        with mock.patch.object(rdev_agent, "run_fixed_subprocess", return_value=0) as run, mock.patch.object(rdev_agent.shutil, "which", return_value="sftp"):
            self.assertEqual(self.run_main(["sftp", "--batch-file", "-"])[0], 0)
            command, environment = run.call_args.args
            self.assertEqual(command[:3], ["sftp", "-P", "18112"])
            self.assertIn("BatchMode=no", command)
            self.assertEqual(environment["RDEV_AGENT_SECRET"], data["token"])
        with mock.patch.object(rdev_agent, "run_fixed_subprocess", return_value=0) as run, mock.patch.object(rdev_agent, "cached_drive_client", return_value=pathlib.Path("drive.py")):
            self.assertEqual(self.run_main(["drive", "capabilities"])[0], 0)
            command, environment = run.call_args.args
            self.assertEqual(command[-3:], ["--base-url", self.base, "capabilities"])
            self.assertEqual(environment["FEIDU_DRIVE_TOKEN"], data["token"])

    def test_developer_transfer_api_uses_fixed_bearer_without_agent_session(self):
        data = self.save_access()
        transfer_id = "33333333-3333-4333-8333-333333333333"
        commands = [
            ["transfer", "create", "--transfer-id", transfer_id, "--direction", "device_to_cloud", "--source-path", "/tmp/test", "--file-name", "test", "--size-bytes", "104857601"],
            ["transfer", "list"], ["transfer", "status", transfer_id], ["transfer", "resume", transfer_id],
        ]
        for command in commands:
            code, output, errors = self.run_main(command)
            self.assertEqual((code, errors), (0, ""))
            self.assertNotIn(data["token"], output)
        self.assertTrue(all(path.startswith("/developer/v1/rdev/transfers") for _, path, _ in Handler.requests))
        self.assertTrue(all(auth == "Bearer " + data["token"] for _, _, auth in Handler.requests))

    def test_lost_create_response_reuses_original_transfer_and_payload(self):
        self.save_access()
        transfer_id = "33333333-3333-4333-8333-333333333333"
        args = ["transfer", "create", "--transfer-id", transfer_id, "--direction", "device_to_cloud", "--source-path", "/tmp/test", "--file-name", "test", "--size-bytes", "104857601", "--wait"]
        transfer = {"transfer_id": transfer_id, "device_id": Handler.device_id, "status": "completed"}
        with mock.patch.object(rdev_agent, "request_json", side_effect=[rdev_agent.RetryableServiceError("lost acknowledgement"), {"transfer": transfer}]) as request, mock.patch.object(rdev_agent.time, "sleep"):
            code, _, errors = self.run_main(args)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0], request.call_args_list[1])
        self.assertEqual(request.call_args.args[3]["transfer_id"], transfer_id)

    def test_transfer_cross_device_rejected_and_internal_secrets_not_reported(self):
        data = self.access()
        transfer_id = "33333333-3333-4333-8333-333333333333"
        transfer = {"transfer_id": transfer_id, "device_id": "OTHER", "status": "running"}
        with self.assertRaisesRegex(rdev_agent.AgentError, "device identity"):
            rdev_agent.validate_transfer(data, transfer, transfer_id)
        transfer.update(token="fdtx_secret", download_url="https://example.test/secret", error_message="fdtx_secret")
        self.assertNotIn("secret", json.dumps(rdev_agent.safe_transfer(transfer)))

    def test_control_redirect_never_forwards_fixed_token(self):
        with self.assertRaisesRegex(rdev_agent.AgentError, "HTTP 302"):
            rdev_agent.request_json(self.base, "GET", "/redirect", token=self.access()["token"])
        self.assertEqual([path for _, path, _ in Handler.requests], ["/redirect"])

    def test_expired_task_resumes_original_id_and_recovers_lost_read(self):
        self.save_access()
        transfer_id = "33333333-3333-4333-8333-333333333333"
        initial = {"transfer_id": transfer_id, "device_id": Handler.device_id, "status": "running", "expires_at_ms": 1}
        resumed = dict(initial, expires_at_ms=int(time.time() * 1000) + 86400000)
        complete = dict(resumed, status="completed")
        args = rdev_agent.build_parser().parse_args(["--state", str(self.state), "transfer", "status", transfer_id, "--wait"])
        with mock.patch.object(rdev_agent, "transfer_request", side_effect=[resumed, rdev_agent.RetryableServiceError("offline"), complete]) as request, mock.patch.object(rdev_agent.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rdev_agent.wait_for_transfer(args, transfer_id, initial), 0)
        self.assertEqual([(call.args[1], call.args[2], call.args[3:] ) for call in request.call_args_list], [("POST", transfer_id, ("resume",)), ("GET", transfer_id, ()), ("GET", transfer_id, ())])

    def test_fixed_revoke_requires_explicit_web_revocation_and_preserves_access(self):
        self.save_access()
        before = self.state.read_bytes()
        code, _, errors = self.run_main(["revoke"])
        self.assertEqual(code, 2)
        self.assertIn("permanent", errors)
        self.assertEqual(self.state.read_bytes(), before)
        self.assertEqual(Handler.requests, [])


if __name__ == "__main__":
    unittest.main()
