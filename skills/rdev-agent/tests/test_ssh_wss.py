import contextlib
import importlib.util
import io
import os
from pathlib import Path
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location("wss_agent", Path(__file__).parents[1] / "scripts/rdev-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class WSSAgentTests(unittest.TestCase):
    def test_raw_default_and_explicit_selection_do_not_probe(self):
        args = agent.build_parser().parse_args(["ssh", "--", "hostname"])
        self.assertEqual(args.transport, "raw")
        with mock.patch.object(agent.socket, "create_connection") as connect:
            self.assertEqual(agent.choose_ssh_transport({}, "wss"), "wss")
            self.assertEqual(agent.choose_ssh_transport({}, "raw"), "raw")
        connect.assert_not_called()

    def test_auto_probes_banner_without_replaying_a_command(self):
        state = {"ssh_host": "example.test", "ssh_port": 1234}
        with mock.patch.object(agent.socket, "create_connection", side_effect=OSError):
            self.assertEqual(agent.choose_ssh_transport(state, "auto"), "wss")
        connection = mock.MagicMock()
        connection.__enter__.return_value.recv.return_value = b"SSH-2.0-rdev\r\n"
        with mock.patch.object(agent.socket, "create_connection", return_value=connection):
            self.assertEqual(agent.choose_ssh_transport(state, "auto"), "raw")
        connection.__enter__.return_value.send.assert_not_called()

    def test_half_close_drains_binary_tail_without_logging_secret(self):
        input_done = threading.Event()
        secret = "fdpat_" + "x" * 43
        class Connection:
            subprotocol = "rdev-browser-v1"
            sent = []
            def send(self, block):
                self.sent.append(block)
                if block == b"":
                    input_done.set()
            def __iter__(self):
                if not input_done.wait(2):
                    raise RuntimeError("missing EOF")
                yield b"\x00\xfftail"
            def close(self):
                pass
        connection = Connection()
        stderr = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"RDEV_WS_URL": "wss://example.test/ssh-ws?device=exact", "RDEV_AGENT_SECRET": secret}),
            mock.patch.object(agent, "require_websocket", return_value=mock.Mock(return_value=connection)) as require,
            mock.patch.object(agent.os, "name", "posix"),
            mock.patch.object(agent.os, "read", side_effect=[b"input", b""]),
            mock.patch.object(agent.os, "write", side_effect=lambda fd, data: len(data)) as write,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(agent.command_ws_stdio(), 0)
        self.assertEqual(connection.sent, [b"input", b""])
        self.assertEqual(bytes(write.call_args.args[1]), b"\x00\xfftail")
        self.assertNotIn(secret, stderr.getvalue())
        kwargs = require.return_value.call_args.kwargs
        self.assertEqual(kwargs["max_size"], 65536)
        self.assertEqual(kwargs["max_queue"], 4)
        self.assertEqual(kwargs["subprotocols"], ["rdev-browser-v1", "rdev-access-ticket." + secret])

    def test_connection_exception_is_redacted(self):
        secret = "fdpat_" + "y" * 43
        stderr = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"RDEV_WS_URL": "wss://example.test/ssh-ws?device=exact", "RDEV_AGENT_SECRET": secret}),
            mock.patch.object(agent, "require_websocket", return_value=mock.Mock(side_effect=RuntimeError(secret))),
            mock.patch.object(agent.os, "name", "posix"),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(agent.command_ws_stdio(), 1)
        self.assertNotIn(secret, stderr.getvalue())

    def test_redirect_does_not_forward_credential(self):
        connect = agent.require_websocket()
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/credential-leak-target")
                self.send_header("Content-Length", "0")
                self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(Exception):
                connect(f"ws://127.0.0.1:{server.server_port}/original", proxy=None,
                        subprotocols=["rdev-browser-v1", "rdev-access-ticket.test-secret"])
            self.assertEqual(requests, ["/original"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
