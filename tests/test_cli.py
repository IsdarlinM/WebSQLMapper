from __future__ import annotations

import io
import json
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout

from lab.vulnerable_server import build_server
from websqlmapper.cli import build_parser, main


class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = build_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/item?id=1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown(); cls.server.server_close(); cls.server.db.close()  # type: ignore[attr-defined]
        cls.thread.join(timeout=2)

    def test_parser_exposes_all_commands(self) -> None:
        parser = build_parser()
        help_text = parser.format_help()
        for command in ["scan", "map", "parse", "report", "template", "web", "update", "doctor"]:
            self.assertIn(command, help_text)

    def test_web_parser_accepts_remote_console_options(self) -> None:
        args = build_parser().parse_args([
            "web", "--host", "0.0.0.0", "--allow-remote", "--token", "0123456789abcdef",
            "--allowed-origin", "https://console.one", "--allowed-origin", "https://console.two",
        ])
        self.assertTrue(args.allow_remote)
        self.assertEqual(args.allowed_origin, ["https://console.one", "https://console.two"])

    def test_scan_json_output_and_human_banner(self) -> None:
        stdout = io.StringIO(); stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--color","never","scan","--url",self.url,"--inject","query:id","--value","1","--context","numeric","--profile","safe","--authorized","--json"])
        self.assertEqual(code, 2)
        data = json.loads(stdout.getvalue())
        self.assertTrue(data["likely_vulnerable"])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            main(["--color","never","doctor"])
        self.assertIn("Web SQL Injector", stdout.getvalue())
        self.assertIn("imr :: v0.4.2", stdout.getvalue())

    def test_cli_errors_are_controlled_without_traceback(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(["scan","--url",self.url,"--inject","query:id"])
        self.assertEqual(code, 1)
        self.assertIn("Authorization acknowledgement required", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


    def test_color_modes_and_banner(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(["--color", "always", "doctor"])
        self.assertEqual(code, 0)
        self.assertIn("\x1b[", stdout.getvalue())
        self.assertIn("Web SQL Injector", stdout.getvalue())

    def test_raw_parse_command(self) -> None:
        raw = "GET /x?id=1 HTTP/1.1\nHost: example.test\n\n"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(["parse","--raw",raw,"--scheme","http"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["request"]["url"], "http://example.test/x?id=1")


if __name__ == "__main__": unittest.main()
