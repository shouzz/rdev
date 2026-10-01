import argparse
import contextlib
import io
import hashlib
import json
import pathlib
import socket
import unittest
from unittest import mock

from test_rdev_agent import rdev_agent as agent


class SSHWebSocketTest(unittest.TestCase):
    def test_distributed_script_hash_and_copies(self):
        root = pathlib.Path(__file__).resolve().parents[3]
        relative = pathlib.Path("skills/rdev-agent/scripts/rdev-agent.py")
        content = (root / relative).read_bytes()
        manifest_path = pathlib.Path("docs/ai-agent-manifest.json")
        manifest = json.loads((root / manifest_path).read_text("utf8"))
        self.assertEqual(manifest["permanent_access"]["tool_sha256"], hashlib.sha256(content).hexdigest())
        for base in ("web/public", "internal/server/static"):
            self.assertEqual((root / base / relative).read_bytes(), content)
            self.assertEqual((root / base / manifest_path).read_bytes(), (root / manifest_path).read_bytes())

    def state(self):
        return {"schema": agent.ACCESS_SCHEMA, "device_id": "device-精确",
                "rdev_base": "https://example.test", "ssh_host": "example.test",
                "ssh_port": 2222, "token": "fdpat_" + "q" * 43}

    def test_auto_uses_banner_and_only_probes_before_command(self):
        probe = mock.MagicMock()
        probe.__enter__.return_value = probe
        probe.recv.return_value = b"SSH-2.0-RDev\r\n"
        with mock.patch.object(socket, "create_connection", return_value=probe) as connect:
            self.assertEqual(agent.choose_ssh_transport(self.state(), "auto"), "raw")
            probe.send.assert_not_called()
            probe.sendall.assert_not_called()
            self.assertEqual(agent.choose_ssh_transport(self.state(), "wss"), "wss")
            self.assertEqual(agent.choose_ssh_transport(self.state(), "raw"), "raw")
            self.assertEqual(connect.call_count, 1)
        with mock.patch.object(socket, "create_connection", side_effect=TimeoutError):
            self.assertEqual(agent.choose_ssh_transport(self.state(), "auto"), "wss")

    def test_wss_no_credential_in_arguments_and_nonzero_not_replayed(self):
        args = argparse.Namespace(state=pathlib.Path("unused"), transport="auto")
        temporary = mock.Mock()
        environment = {"RDEV_AGENT_SECRET": self.state()["token"]}
        with (mock.patch.object(agent, "maintained_state", return_value=(self.state(), {})),
              mock.patch.object(agent, "choose_ssh_transport", return_value="wss"),
              mock.patch.object(agent, "require_websocket"),
              mock.patch.object(agent.shutil, "which", return_value="ssh"),
              mock.patch.object(agent, "askpass_environment", return_value=(temporary, environment)),
              mock.patch.object(agent, "run_fixed_subprocess", return_value=37) as run):
            self.assertEqual(agent.run_open_ssh(args, "ssh", ["device@example.test", "command"]), 37)
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertNotIn(self.state()["token"], " ".join(argv))
            self.assertIn("PreferredAuthentications=none", argv)
            self.assertIn("ClearAllForwardings=yes", argv)
            self.assertIn("ControlPath=none", argv)
            self.assertTrue(environment["RDEV_WS_URL"].startswith("wss://example.test/ssh-ws?device="))
            self.assertNotIn(self.state()["token"], environment["RDEV_WS_URL"])
        temporary.cleanup.assert_called_once()

    def test_wss_rejects_forwarding_before_start(self):
        args = argparse.Namespace(state=pathlib.Path("unused"), transport="wss", local_forward=["127.0.0.1:1:localhost:2"])
        temporary = mock.Mock()
        with (mock.patch.object(agent, "maintained_state", return_value=(self.state(), {})),
              mock.patch.object(agent.shutil, "which", return_value="ssh"),
              mock.patch.object(agent, "askpass_environment", return_value=(temporary, {})),
              mock.patch.object(agent, "run_fixed_subprocess") as run):
            with self.assertRaisesRegex(agent.AgentError, "port forwarding"):
                agent.run_open_ssh(args, "ssh", [])
            run.assert_not_called()
        temporary.cleanup.assert_called_once()

    def test_proxy_error_never_echoes_headers(self):
        secret = self.state()["token"]
        library = mock.Mock()
        library.create_connection.side_effect = RuntimeError("response contains " + secret)
        errors = io.StringIO()
        with (mock.patch.dict(agent.os.environ, {"RDEV_WS_URL": "wss://example.test/ssh-ws?device=test",
                                                "RDEV_AGENT_SECRET": secret}),
              mock.patch.object(agent, "require_websocket", return_value=library),
              mock.patch.object(agent.os, "name", "posix"),
              contextlib.redirect_stderr(errors)):
            self.assertEqual(agent.command_ws_stdio(), 1)
        self.assertNotIn(secret, errors.getvalue())
        self.assertEqual(library.create_connection.call_args.kwargs["redirect_limit"], 0)


if __name__ == "__main__":
    unittest.main()
