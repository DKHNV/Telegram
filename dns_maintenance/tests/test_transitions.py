import unittest
from datetime import datetime, timedelta, timezone

from dns_maintenance.core import DNSResult, Settings, aggregate_resolver_results, apply_check_result, new_host_state, revive_expired


SETTINGS = Settings(
    resolvers=("1.1.1.1", "8.8.8.8", "9.9.9.9"),
    timeout_seconds=2.0,
    lifetime_seconds=4.0,
    negative_votes_required=2,
    suspect_after_failures=3,
    quarantine_after_failures=7,
    expire_after_days=30,
    max_workers=20,
)

NEGATIVE = DNSResult("NEGATIVE", tuple(), None, {})
TRANSIENT = DNSResult("TRANSIENT", tuple(), None, {})
OK = DNSResult("OK", ("203.0.113.10",), "example.com", {})


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 20, tzinfo=timezone.utc)

    def test_legacy_active_becomes_suspect_only_on_third_negative(self):
        state = new_host_state("example.com", self.now, "legacy_active", legacy_active=True)
        for i in range(2):
            apply_check_result(state, NEGATIVE, self.now + timedelta(days=i), SETTINGS)
            self.assertEqual(state["status"], "active")
        apply_check_result(state, NEGATIVE, self.now + timedelta(days=2), SETTINGS)
        self.assertEqual(state["status"], "suspect")

    def test_seventh_negative_quarantines(self):
        state = new_host_state("example.com", self.now, "legacy_active", legacy_active=True)
        for i in range(7):
            apply_check_result(state, NEGATIVE, self.now + timedelta(days=i), SETTINGS)
        self.assertEqual(state["status"], "quarantine")
        self.assertIsNotNone(state["quarantined_at"])

    def test_transient_does_not_advance_failure_counter(self):
        state = new_host_state("example.com", self.now, "legacy_active", legacy_active=True)
        apply_check_result(state, NEGATIVE, self.now, SETTINGS)
        before = state["consecutive_negative_checks"]
        apply_check_result(state, TRANSIENT, self.now + timedelta(days=1), SETTINGS)
        self.assertEqual(state["consecutive_negative_checks"], before)
        self.assertEqual(state["status"], "active")

    def test_success_restores_quarantined_host(self):
        state = new_host_state("example.com", self.now, "legacy_active", legacy_active=True)
        for i in range(7):
            apply_check_result(state, NEGATIVE, self.now + timedelta(days=i), SETTINGS)
        self.assertEqual(state["status"], "quarantine")
        apply_check_result(state, OK, self.now + timedelta(days=8), SETTINGS)
        self.assertEqual(state["status"], "active")
        self.assertEqual(state["consecutive_negative_checks"], 0)
        self.assertEqual(state["ipv4"], ["203.0.113.10"])

    def test_quarantine_expires_after_30_days_of_continued_negative(self):
        state = new_host_state("example.com", self.now, "legacy_active", legacy_active=True)
        for i in range(7):
            apply_check_result(state, NEGATIVE, self.now + timedelta(days=i), SETTINGS)
        quarantined_at = datetime.fromisoformat(state["quarantined_at"].replace("Z", "+00:00"))
        apply_check_result(state, NEGATIVE, quarantined_at + timedelta(days=30), SETTINGS)
        self.assertEqual(state["status"], "expired")

    def test_new_pending_host_is_not_active_until_success(self):
        state = new_host_state("example.com", self.now, "manual", legacy_active=False)
        apply_check_result(state, NEGATIVE, self.now, SETTINGS)
        self.assertEqual(state["status"], "pending")
        self.assertFalse(state["ever_validated"])
        apply_check_result(state, OK, self.now + timedelta(days=1), SETTINGS)
        self.assertEqual(state["status"], "active")
        self.assertTrue(state["ever_validated"])

    def test_any_positive_resolver_wins(self):
        result = aggregate_resolver_results({
            "1.1.1.1": {"status": "NXDOMAIN", "ipv4": []},
            "8.8.8.8": {"status": "OK", "ipv4": ["203.0.113.10"], "canonical_name": "example.com"},
            "9.9.9.9": {"status": "TIMEOUT", "ipv4": []},
        }, 2)
        self.assertEqual(result.aggregate, "OK")
        self.assertEqual(result.ipv4, ("203.0.113.10",))

    def test_two_definitive_negative_votes_are_negative(self):
        result = aggregate_resolver_results({
            "1.1.1.1": {"status": "NXDOMAIN", "ipv4": []},
            "8.8.8.8": {"status": "NO_A", "ipv4": []},
            "9.9.9.9": {"status": "TIMEOUT", "ipv4": []},
        }, 2)
        self.assertEqual(result.aggregate, "NEGATIVE")

    def test_single_negative_plus_transient_failures_is_transient(self):
        result = aggregate_resolver_results({
            "1.1.1.1": {"status": "NXDOMAIN", "ipv4": []},
            "8.8.8.8": {"status": "TIMEOUT", "ipv4": []},
            "9.9.9.9": {"status": "NO_NAMESERVERS", "ipv4": []},
        }, 2)
        self.assertEqual(result.aggregate, "TRANSIENT")

    def test_old_quarantine_does_not_expire_on_transient_result(self):
        state = new_host_state("example.com", self.now, "legacy_active", legacy_active=True)
        for i in range(7):
            apply_check_result(state, NEGATIVE, self.now + timedelta(days=i), SETTINGS)
        quarantined_at = datetime.fromisoformat(state["quarantined_at"].replace("Z", "+00:00"))
        apply_check_result(state, TRANSIENT, quarantined_at + timedelta(days=60), SETTINGS)
        self.assertEqual(state["status"], "quarantine")

    def test_requeued_expired_host_requires_new_success_before_active(self):
        state = new_host_state("example.com", self.now, "legacy_active", legacy_active=True)
        state["status"] = "expired"
        state["expired_at"] = "2026-08-01T00:00:00Z"
        revive_expired(state, self.now, "manual")
        self.assertEqual(state["status"], "pending")
        self.assertFalse(state["ever_validated"])
        apply_check_result(state, NEGATIVE, self.now, SETTINGS)
        self.assertEqual(state["status"], "pending")
        apply_check_result(state, OK, self.now + timedelta(days=1), SETTINGS)
        self.assertEqual(state["status"], "active")


if __name__ == "__main__":
    unittest.main()
