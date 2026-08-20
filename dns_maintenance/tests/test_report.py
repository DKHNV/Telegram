import unittest
from datetime import datetime, timezone

from dns_maintenance.report import render_report


NOW = datetime(2026, 8, 20, 8, 0, tzinfo=timezone.utc)


class ReportTests(unittest.TestCase):
    def test_report_contains_counts_failures_and_discovery(self):
        collection = {"active": "Telegram_DNS"}
        dns_state = {
            "updated_at": "2026-08-20T08:00:00Z",
            "hosts": {
                "telegram.org": {
                    "status": "active",
                    "first_seen": "2026-08-19T08:00:00Z",
                    "sources": ["legacy_active"],
                },
                "new.telegram.org": {
                    "status": "active",
                    "first_seen": "2026-08-20T08:00:00Z",
                    "sources": ["discovered"],
                },
            },
        }
        service_state = {
            "updated_at": "2026-08-20T08:00:00Z",
            "hosts": {
                "telegram.org": {
                    "status": "alive",
                    "last_result": "ALIVE",
                    "stability_score": 100.0,
                    "history_samples": 4,
                },
                "new.telegram.org": {
                    "status": "unknown",
                    "last_result": "FAILURE",
                    "consecutive_failures": 1,
                    "last_failure": {"type": "TIMEOUT"},
                    "last_ipv4": ["1.2.3.4"],
                    "stability_score": 0.0,
                    "history_samples": 1,
                    "last_check": "2026-08-20T08:00:00Z",
                },
            },
        }
        discovery_state = {
            "updated_at": "2026-08-20T07:59:00Z",
            "sources": {
                "certspotter": {
                    "telegram.org": {
                        "caught_up": True,
                        "last_poll": "2026-08-20T07:59:00Z",
                    }
                }
            },
        }
        text = render_report(
            "telegram",
            collection,
            dns_state,
            service_state,
            discovery_state,
            ["telegram.org", "new.telegram.org"],
            NOW,
        )
        self.assertIn("# Telegram DNS Maintenance Report", text)
        self.assertIn("| HTTPS/TLS | Alive | 1 |", text)
        self.assertIn("TIMEOUT", text)
        self.assertIn("New CT-discovered hosts imported in the latest DNS-maintenance run: **1**", text)
        self.assertIn("`new.telegram.org`", text)


if __name__ == "__main__":
    unittest.main()
