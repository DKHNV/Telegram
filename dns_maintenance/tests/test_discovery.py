import unittest

from dns_maintenance.discover_dns import extract_candidates, is_within_root


class DiscoveryTests(unittest.TestCase):
    def test_is_within_root(self):
        self.assertTrue(is_within_root("telegram.org", "telegram.org"))
        self.assertTrue(is_within_root("web.telegram.org", "telegram.org"))
        self.assertFalse(is_within_root("nottelegram.org", "telegram.org"))
        self.assertFalse(is_within_root("telegram.org.example.com", "telegram.org"))

    def test_extract_candidates_filters_wildcards_and_other_domains(self):
        issuances = [
            {
                "dns_names": [
                    "web.telegram.org",
                    "API.Telegram.org",
                    "*.telegram.org",
                    "example.com",
                    "web.telegram.org",
                ]
            }
        ]
        self.assertEqual(
            extract_candidates(issuances, "telegram.org"),
            {"web.telegram.org", "api.telegram.org"},
        )

    def test_extract_candidates_handles_bad_payload(self):
        issuances = [
            {"dns_names": "web.telegram.org"},
            {"dns_names": [None, 123, "desktop.telegram.org"]},
        ]
        self.assertEqual(extract_candidates(issuances, "telegram.org"), {"desktop.telegram.org"})


if __name__ == "__main__":
    unittest.main()
