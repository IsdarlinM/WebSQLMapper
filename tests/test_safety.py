from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from websqlmapper.safety import SafetyError, is_private_or_loopback_target, require_authorization, require_private_mapping_target


class SafetyTests(unittest.TestCase):
    def test_localhost_is_private(self) -> None:
        self.assertTrue(is_private_or_loopback_target("http://127.0.0.1:8080/"))
        self.assertTrue(is_private_or_loopback_target("http://localhost:8080/"))

    def test_public_ip_is_not_private(self) -> None:
        self.assertFalse(is_private_or_loopback_target("https://1.1.1.1/"))


    def test_mapping_resolution_change_is_rejected(self) -> None:
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
        with patch("websqlmapper.safety.socket.getaddrinfo", return_value=private):
            expected = require_private_mapping_target("http://lab.internal/item")
        with patch("websqlmapper.safety.socket.getaddrinfo", return_value=public):
            with self.assertRaises(SafetyError):
                require_private_mapping_target("http://lab.internal/item", expected_addresses=expected)

    def test_authorization_is_required(self) -> None:
        with self.assertRaises(SafetyError):
            require_authorization(False)


if __name__ == "__main__":
    unittest.main()
