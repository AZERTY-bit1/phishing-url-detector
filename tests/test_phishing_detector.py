import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phishing_detector import analyze  # noqa: E402


class TestPhishing(unittest.TestCase):
    def test_safe(self):
        self.assertEqual(analyze("https://www.wikipedia.org/")["verdict"], "PROBABLY SAFE")

    def test_brand_lookalike(self):
        r = analyze("http://paypa1-secure-login.xyz/verify/account")
        self.assertEqual(r["verdict"], "DANGEROUS")

    def test_ip_and_at(self):
        r = analyze("http://google.com@192.168.1.10/login")
        self.assertGreaterEqual(r["score"], 6)

    def test_real_brand_ok(self):
        self.assertNotEqual(analyze("https://www.paypal.com/")["verdict"], "DANGEROUS")


if __name__ == "__main__":
    unittest.main()
