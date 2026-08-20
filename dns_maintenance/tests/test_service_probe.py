import unittest
from datetime import datetime, timezone

from dns_maintenance.service_probe import (
    aggregate_attempts,
    apply_service_result,
    new_service_state,
    parse_http_status,
)


NOW = datetime(2026, 8, 20, 7, 30, tzinfo=timezone.utc)


class ServiceProbeTests(unittest.TestCase):
    def test_parse_http_status(self):
        self.assertEqual(parse_http_status(b"HTTP/1.1 302 Found\r\nLocation: /x\r\n"), 302)
        self.assertEqual(parse_http_status(b"HTTP/2 200 OK\r\n"), 200)
        self.assertIsNone(parse_http_status(b"not http"))

    def test_any_https_success_means_alive(self):
        attempts = [
            {"status": "TIMEOUT"},
            {"status": "HTTPS_OK", "http_status": 403},
        ]
        self.assertEqual(aggregate_attempts(attempts), "ALIVE")

    def test_tls_only_success_means_alive(self):
        self.assertEqual(aggregate_attempts([{"status": "TLS_OK"}]), "ALIVE")

    def test_no_attempts_is_skipped(self):
        self.assertEqual(aggregate_attempts([]), "SKIPPED")

    def test_failures_become_suspect_then_dead(self):
        state = new_service_state("example.com", NOW)
        for _ in range(2):
            apply_service_result(state, "FAILURE", [{"status": "TIMEOUT"}], ["1.2.3.4"], NOW, 3, 7)
        self.assertEqual(state["status"], "unknown")
        apply_service_result(state, "FAILURE", [{"status": "TIMEOUT"}], ["1.2.3.4"], NOW, 3, 7)
        self.assertEqual(state["status"], "suspect")
        for _ in range(4):
            apply_service_result(state, "FAILURE", [{"status": "TIMEOUT"}], ["1.2.3.4"], NOW, 3, 7)
        self.assertEqual(state["status"], "dead")

    def test_success_recovers_dead(self):
        state = new_service_state("example.com", NOW)
        state["status"] = "dead"
        state["consecutive_failures"] = 7
        apply_service_result(state, "ALIVE", [{"status": "HTTPS_OK", "http_status": 200}], ["1.2.3.4"], NOW, 3, 7)
        self.assertEqual(state["status"], "alive")
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertTrue(state["ever_alive"])

    def test_skipped_does_not_advance_failure_counter(self):
        state = new_service_state("example.com", NOW)
        state["status"] = "alive"
        state["ever_alive"] = True
        state["consecutive_failures"] = 2
        apply_service_result(state, "SKIPPED", [], [], NOW, 3, 7)
        self.assertEqual(state["status"], "alive")
        self.assertEqual(state["consecutive_failures"], 2)


if __name__ == "__main__":
    unittest.main()
