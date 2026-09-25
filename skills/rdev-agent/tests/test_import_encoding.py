"""Real subprocess regression for Windows code-page independent imports."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / 'scripts' / 'rdev-agent.py'
spec = importlib.util.spec_from_file_location('agent', SCRIPT)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class ImportEncodingTests(unittest.TestCase):
    def test_encoded_imports_and_rejected_input_preserve_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory) / 'access.json'
            for device in ('我的电脑', '我的电脑-2'):
                access = dict(schema='rdev-device-access.v1', device_id=device,
                              rdev_base='https://r.example.test', api_base='https://pan.example.test',
                              ssh_host='r.example.test', ssh_port=18112, token='fdpat_' + 'A' * 43)
                raw = json.dumps(access, ensure_ascii=False)
                def run(payload, *args):
                    return subprocess.run([sys.executable, str(SCRIPT), '--state', str(state),
                                           '--device', device, '--import-stdin', *args], input=payload,
                                          capture_output=True, env=dict(os.environ, PYTHONIOENCODING='gbk'), timeout=20)
                for encoding in ('utf-8', 'utf-8-sig', 'utf-16', 'utf-32'):
                    with self.subTest(device=device, encoding=encoding):
                        result = run(raw.encode(encoding), '--replace')
                        self.assertEqual(result.returncode, 0, result.stderr.decode('ascii', errors='replace'))
                        self.assertEqual(agent.read_state(state), access)
                        self.assertNotIn(access['token'].encode(), result.stdout + result.stderr)
                        if os.name == 'nt':
                            self.assertTrue(state.read_bytes().startswith(agent.WINDOWS_STATE_MAGIC))
                            self.assertNotIn(access['token'].encode(), state.read_bytes())
                before = state.read_bytes()
                for payload in (raw.encode('gbk'), b'\xff', b'x' * 65537,
                                raw.replace(device, 'wrong-device').encode(),
                                raw.replace(device, '\ufffd').encode(),
                                raw.replace(device, '中' * 43).encode(),
                                raw.replace(device, r'\ud800').encode()):
                    result = run(payload)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(state.read_bytes(), before)
                    self.assertNotIn(access['token'].encode(), result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
