from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class PythonCompatibilityTests(unittest.TestCase):
    def test_project_python_syntax_parses_as_python_310(self) -> None:
        for root in (ROOT / "websqlmapper", ROOT / "lab", ROOT / "tests"):
            for path in root.rglob("*.py"):
                source = path.read_text(encoding="utf-8")
                try:
                    ast.parse(source, filename=str(path), feature_version=(3, 10))
                except SyntaxError as exc:
                    self.fail(f"{path} is not Python 3.10 syntax compatible: {exc}")

    def test_runtime_is_supported(self) -> None:
        self.assertGreaterEqual(sys.version_info[:2], (3, 10))

if __name__ == "__main__": unittest.main()
