from __future__ import annotations

import unittest

from websqlmapper.safety import SafetyError, is_private_or_loopback_target, require_authorization


class SafetyTests(unittest.TestCase):
    def test_localhost_is_private(self) -> None:
        self.assertTrue(is_private_or_loopback_target("http://127.0.0.1:8080/"))
        self.assertTrue(is_private_or_loopback_target("http://localhost:8080/"))

    def test_public_ip_is_not_private(self) -> None:
        self.assertFalse(is_private_or_loopback_target("https://1.1.1.1/"))

    def test_authorization_is_required(self) -> None:
        with self.assertRaises(SafetyError):
            require_authorization(False)


if __name__ == "__main__":
    unittest.main()
