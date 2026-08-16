from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
        self.assertNotIn("powershell", text.lower())
        self.assertIn("Python.Python.3.13", text)
        self.assertIn("Python.Python.3.10", text)
        self.assertIn("sys.version_info >= (3,10)", text)
        self.assertIn("winget install", text)
        self.assertIn("setx WEBSQLMAPPER_HOME", text)
        self.assertIn("HKCU\\Environment /v Path", text)
        self.assertIn("websqlmapper.cmd --version", (ROOT / ".github" / "workflows" / "installers.yml").read_text())
        labels = set(re.findall(r"(?m)^:([A-Za-z0-9_-]+)\s*$", text))
        targets = set(re.findall(r"goto\s+:([A-Za-z0-9_-]+)", text, flags=re.I))
        self.assertTrue(targets <= labels, f"missing labels: {targets - labels}")
        self.assertEqual(text.count("("), text.count(")"), "unbalanced batch parentheses")

    def test_windows_docker_smoke_definition_exists(self) -> None:
        text = (ROOT / "docker" / "Dockerfile.windows").read_text()
        self.assertIn("windowsservercore", text.lower())
        self.assertIn("scripts\\install.cmd", text)
        self.assertIn("websqlmapper.cmd --version", text)
        smoke = (ROOT / "scripts" / "test-windows-docker.cmd").read_text()
        self.assertIn("Dockerfile.windows", smoke)
        self.assertIn("windows", smoke.lower())


if __name__ == "__main__": unittest.main()
