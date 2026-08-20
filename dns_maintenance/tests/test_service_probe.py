import unittest
from datetime import datetime, timezone

from dns_maintenance.service_probe import (
    aggregate_attempts,
    apply_service_result,
    build_failure_record,
    new_service_state,
    normalize_service_state_entry,
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


    def test_failure_record_is_structured(self):
        attempts = [
            {"ip": "1.2.3.4", "port": 443, "status": "TIMEOUT"},
            {"ip": "5.6.7.8", "port": 443, "status": "TLS_CERT_ERROR", "detail": "certificate mismatch"},
        ]
        record = build_failure_record(attempts, NOW)
        self.assertEqual(record["type"], "MULTIPLE")
        self.assertEqual(record["statuses"], ["TIMEOUT", "TLS_CERT_ERROR"])
        self.assertEqual(len(record["attempts"]), 2)
        self.assertEqual(record["attempts"][1]["detail"], "certificate mismatch")

    def test_legacy_failure_timestamp_is_migrated(self):
        state = {"last_failure": "2026-08-20T07:00:00Z"}
        normalize_service_state_entry(state)
        self.assertEqual(state["last_failure"]["at"], "2026-08-20T07:00:00Z")
        self.assertEqual(state["last_failure"]["type"], "LEGACY")

    def test_apply_failure_saves_structured_last_failure(self):
        state = new_service_state("example.com", NOW)
        attempts = [{"ip": "1.2.3.4", "port": 443, "status": "REFUSED"}]
        apply_service_result(state, "FAILURE", attempts, ["1.2.3.4"], NOW, 3, 7)
        self.assertIsInstance(state["last_failure"], dict)
        self.assertEqual(state["last_failure"]["type"], "REFUSED")
        self.assertEqual(state["last_failure"]["attempts"][0]["ip"], "1.2.3.4")

    def test_success_keeps_previous_failure_for_history(self):
        state = new_service_state("example.com", NOW)
        apply_service_result(
            state, "FAILURE", [{"ip": "1.2.3.4", "port": 443, "status": "TIMEOUT"}],
            ["1.2.3.4"], NOW, 3, 7
        )
        previous = state["last_failure"]
        apply_service_result(
            state, "ALIVE", [{"ip": "1.2.3.4", "port": 443, "status": "HTTPS_OK", "http_status": 200}],
            ["1.2.3.4"], NOW, 3, 7
        )
        self.assertEqual(state["last_failure"], previous)
        self.assertEqual(state["status"], "alive")

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
