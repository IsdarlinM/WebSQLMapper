from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PythonCompatibilityTests(unittest.TestCase):
    def test_all_project_python_sources_parse_with_python_310_grammar(self) -> None:
        failures: list[str] = []
        for dirname in ("websqlmapper", "lab", "tests"):
            for path in (ROOT / dirname).rglob("*.py"):
                try:
                    ast.parse(path.read_text(), filename=str(path), feature_version=(3, 10))
                except SyntaxError as exc:
                    failures.append(f"{path.relative_to(ROOT)}: {exc}")
        self.assertFalse(failures, "Python 3.10 grammar incompatibilities:\n" + "\n".join(failures))

    def test_runtime_used_by_test_suite_satisfies_declared_floor(self) -> None:
        self.assertGreaterEqual(sys.version_info[:2], (3, 10))

    def test_runtime_dependency_declares_compatible_floor(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text()
        self.assertIn('requires-python = ">=3.10"', pyproject)
        self.assertIn('dependencies = ["requests>=2.32,<3"]', pyproject)


if __name__ == "__main__":
    unittest.main()
