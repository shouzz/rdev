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

    def log_message(self, *_):
        return

    def respond(self, data):
        payload = envelope(data)
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
        if self.path == "/api/config":
            payload = json.dumps({"sshPort": "18112"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.respond({"transfer": {"transfer_id": self.path.split("/")[-1], "agent_session_id": self.session_id, "status": "completed"}})

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
            self.respond({"transfer": {"transfer_id": body["transfer_id"], "agent_session_id": self.session_id, "status": "queued"}})
        else:
            self.respond({"transfer": {"transfer_id": self.path.split("/")[-2], "agent_session_id": self.session_id, "status": "paused"}})

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


if __name__ == "__main__":
    unittest.main()
