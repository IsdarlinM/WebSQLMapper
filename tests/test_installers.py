from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_windows_env_module():
    path = ROOT / "scripts" / "windows_env.py"
    spec = importlib.util.spec_from_file_location("windows_env_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load windows_env.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InstallerTests(unittest.TestCase):
    def test_linux_installers_parse_and_have_environment_setup(self) -> None:
        for name in ["install-linux.sh", "uninstall-linux.sh", "test-install-linux.sh", "test-install-linux-online.sh"]:
            result = subprocess.run(["bash", "-n", str(ROOT / "scripts" / name)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        text = (ROOT / "scripts" / "install-linux.sh").read_text()
        self.assertIn("python3-venv", text)
        self.assertIn("WEBSQLMAPPER_HOME", text)
        self.assertIn("printf 'export PATH=%q:\"$PATH\"\\n' \"$BIN_DIR\"", text)
        for manager in ["apt-get", "dnf", "pacman", "apk", "pkg", "brew"]:
            self.assertIn(manager, text)

    def test_windows_installer_control_flow_and_environment(self) -> None:
        text = (ROOT / "scripts" / "install.cmd").read_text()
        self.assertNotIn("powershell.exe", text.lower())
        self.assertNotIn("pwsh.exe", text.lower())
        self.assertNotRegex(text.lower(), r"(?m)^\s*(?:powershell|pwsh)\b")
        self.assertIn("Python.Python.3.13", text)
        self.assertIn("Python.Python.3.10", text)
        self.assertIn("sys.version_info >= (3,10)", text)
        self.assertIn("winget install", text)
        self.assertIn('call :capture_selected_version', text)
        self.assertIn('call :capture_venv_version', text)
        self.assertNotRegex(text.lower(), r"for\s+/f[^\n]+python[^\n]+-c")
        self.assertIn('call "%WRAPPER%" --version', text)
        self.assertIn('call websqlmapper --version', text)
        self.assertIn('set "PATH=%BIN_DIR%;%PATH%"', text)
        self.assertIn('windows_env.py" --home', text)
        self.assertIn('endlocal & set "WEBSQLMAPPER_HOME=', text)
        labels = set(re.findall(r"(?m)^:([A-Za-z0-9_-]+)\s*$", text))
        targets = set(re.findall(r"goto\s+:([A-Za-z0-9_-]+)", text, flags=re.I))
        self.assertTrue(targets <= labels, f"missing labels: {targets - labels}")
        self.assertEqual(text.count("("), text.count(")"), "unbalanced batch parentheses")

    def test_windows_environment_helper_is_idempotent(self) -> None:
        module = _load_windows_env_module()
        current = r"C:\Tools;C:\Users\demo\AppData\Local\WebSQLMapper\bin"
        same = module.merge_path(current, r"c:/users/demo/AppData/Local/WebSQLMapper/bin/")
        self.assertEqual(same, current)
        added = module.merge_path(r"C:\Tools", r"C:\WebSQLMapper\bin")
        self.assertEqual(added, r"C:\Tools;C:\WebSQLMapper\bin")
        help_run = subprocess.run([sys.executable, str(ROOT / "scripts" / "windows_env.py"), "--help"], capture_output=True, text=True)
        self.assertEqual(help_run.returncode, 0, help_run.stderr)

    def test_windows_ci_calls_batch_files_and_docker_smoke_exists(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "installers.yml").read_text()
        self.assertIn("call scripts\\install.cmd", workflow)
        self.assertIn("call %RUNNER_TEMP%\\WebSQLMapper\\bin\\websqlmapper.cmd --version", workflow)
        dockerfile = (ROOT / "docker" / "Dockerfile.windows").read_text()
        self.assertIn("windowsservercore", dockerfile.lower())
        self.assertIn("RUN call scripts\\install.cmd", dockerfile)
        self.assertIn("RUN call C:\\WebSQLMapperTest\\bin\\websqlmapper.cmd --version", dockerfile)
        smoke = (ROOT / "scripts" / "test-windows-docker.cmd").read_text()
        self.assertIn("Dockerfile.windows", smoke)
        self.assertIn("windows", smoke.lower())


if __name__ == "__main__":
    unittest.main()
