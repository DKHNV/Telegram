from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Settings:
    resolvers: tuple[str, ...]
    timeout_seconds: float
    lifetime_seconds: float
    negative_votes_required: int
    suspect_after_failures: int
    quarantine_after_failures: int
    expire_after_days: int
    max_workers: int


@dataclass(frozen=True)
class DNSResult:
    aggregate: str  # OK | NEGATIVE | TRANSIENT
    ipv4: tuple[str, ...]
    canonical_name: str | None
    resolver_results: dict[str, dict[str, Any]]


def aggregate_resolver_results(
    resolver_results: dict[str, dict[str, Any]],
    negative_votes_required: int,
) -> DNSResult:
    all_ipv4: set[str] = set()
    canonical_names: list[str] = []
    negative_votes = 0

    for result in resolver_results.values():
        status = result.get("status")
        if status == "OK":
            all_ipv4.update(result.get("ipv4", []))
            canonical = result.get("canonical_name")
            if canonical:
                canonical_names.append(str(canonical))
        elif status in {"NXDOMAIN", "NO_A"}:
            negative_votes += 1

    if all_ipv4:
        aggregate = "OK"
    elif negative_votes >= negative_votes_required:
        aggregate = "NEGATIVE"
    else:
        aggregate = "TRANSIENT"

    canonical_name = sorted(canonical_names)[0] if canonical_names else None
    return DNSResult(
        aggregate=aggregate,
        ipv4=tuple(sorted(all_ipv4, key=lambda x: ipaddress.ip_address(x))),
        canonical_name=canonical_name,
        resolver_results=resolver_results,
    )


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def new_host_state(host: str, now: datetime, source: str, legacy_active: bool = False) -> dict[str, Any]:
    stamp = iso(now)
    return {
        "hostname": host,
        "status": "active" if legacy_active else "pending",
        "sources": [source],
        "first_seen": stamp,
        "last_check": None,
        "last_success": None,
        "last_failure": None,
        "last_result": "UNTESTED",
        "consecutive_negative_checks": 0,
        "ever_validated": bool(legacy_active),
        "ipv4": [],
        "canonical_name": None,
        "quarantined_at": None,
        "expired_at": None,
        "resolver_results": {},
    }


def add_source(host_state: dict[str, Any], source: str) -> None:
    sources = set(host_state.get("sources", []))
    sources.add(source)
    host_state["sources"] = sorted(sources)


def revive_expired(host_state: dict[str, Any], now: datetime, source: str) -> None:
    add_source(host_state, source)
    host_state["status"] = "pending"
    host_state["consecutive_negative_checks"] = 0
    host_state["quarantined_at"] = None
    host_state["expired_at"] = None
    host_state["last_result"] = "REQUEUED"
    host_state["last_check"] = None
    host_state["ever_validated"] = False


def apply_check_result(
    host_state: dict[str, Any],
    result: DNSResult,
    now: datetime,
    settings: Settings,
) -> tuple[str, str]:
    """Apply one aggregate DNS result and return (old_status, new_status)."""
    old_status = host_state.get("status", "pending")
    stamp = iso(now)
    host_state["last_check"] = stamp
    host_state["resolver_results"] = result.resolver_results

    if result.aggregate == "OK":
        host_state["status"] = "active"
        host_state["last_success"] = stamp
        host_state["last_result"] = "OK"
        host_state["consecutive_negative_checks"] = 0
        host_state["ever_validated"] = True
        host_state["ipv4"] = list(result.ipv4)
        host_state["canonical_name"] = result.canonical_name
        host_state["quarantined_at"] = None
        host_state["expired_at"] = None
        return old_status, "active"

    if result.aggregate == "TRANSIENT":
        # A transient network/DNS failure must never advance deletion.
        host_state["last_result"] = "TRANSIENT"
        return old_status, host_state.get("status", "pending")

    host_state["last_failure"] = stamp
    host_state["last_result"] = "NEGATIVE"
    host_state["ipv4"] = []
    host_state["canonical_name"] = None
    failures = int(host_state.get("consecutive_negative_checks", 0)) + 1
    host_state["consecutive_negative_checks"] = failures

    if old_status == "quarantine":
        quarantined_at = parse_iso(host_state.get("quarantined_at"))
        if quarantined_at is None:
            quarantined_at = now
            host_state["quarantined_at"] = stamp
        age_days = (now - quarantined_at).total_seconds() / 86400
        if age_days >= settings.expire_after_days:
            host_state["status"] = "expired"
            host_state["expired_at"] = stamp
            return old_status, "expired"
        return old_status, "quarantine"

    if failures >= settings.quarantine_after_failures:
        host_state["status"] = "quarantine"
        if not host_state.get("quarantined_at"):
            host_state["quarantined_at"] = stamp
        return old_status, "quarantine"

    if failures >= settings.suspect_after_failures:
        host_state["status"] = "suspect"
        return old_status, "suspect"

    host_state["status"] = "active" if host_state.get("ever_validated") else "pending"
    return old_status, host_state["status"]
