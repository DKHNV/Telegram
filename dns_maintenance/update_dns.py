#!/usr/bin/env python3
"""Maintain DNS hostname lists with conservative automatic lifecycle rules.

The script is designed to run both locally and in GitHub Actions.
All collection paths in config.json are resolved relative to --repo-root.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import ipaddress
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import dns.exception
import dns.resolver

try:
    from dns_maintenance.core import (
        DNSResult,
        Settings,
        add_source,
        aggregate_resolver_results,
        apply_check_result,
        iso,
        new_host_state,
        revive_expired,
    )
except ModuleNotFoundError:  # Allows direct: python dns_maintenance/update_dns.py
    from core import (
        DNSResult,
        Settings,
        add_source,
        aggregate_resolver_results,
        apply_check_result,
        iso,
        new_host_state,
        revive_expired,
    )

STATE_VERSION = 1
DEFINITIVE_NEGATIVE = {"NXDOMAIN", "NO_A"}
TRANSIENT_RESULTS = {"TIMEOUT", "NO_NAMESERVERS", "DNS_ERROR", "ERROR"}
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def write_host_file(path: Path, hosts: Iterable[str]) -> None:
    ordered = sorted(set(hosts))
    content = "".join(f"{host}\n" for host in ordered)
    atomic_write_text(path, content)


def normalize_hostname(raw: str) -> str | None:
    value = raw.strip()
    if not value or value.startswith("#"):
        return None

    # Strip an inline comment only when it is separated by whitespace.
    value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
    if not value:
        return None

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    else:
        # Accept accidental host:port input, but do not treat IPv6 as a hostname.
        if value.count(":") == 1:
            host_part, port_part = value.rsplit(":", 1)
            if port_part.isdigit():
                value = host_part

    value = value.rstrip(".").strip().lower()
    if value.startswith("*."):
        value = value[2:]

    if not value:
        return None

    try:
        ipaddress.ip_address(value)
        return None  # This pipeline intentionally maintains DNS names, not raw IPs.
    except ValueError:
        pass

    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(ascii_name) > 253:
        return None

    labels = ascii_name.split(".")
    if len(labels) < 2:
        return None
    if any(not label or not HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None

    return ascii_name


def read_host_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    result: set[str] = set()
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        host = normalize_hostname(line)
        if host:
            result.add(host)
        elif line.strip() and not line.lstrip().startswith("#"):
            print(f"WARN {path}:{line_no}: skipped invalid hostname: {line.strip()!r}")
    return result


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def load_config(path: Path) -> dict[str, Any]:
    config = load_json(path, None)
    if not isinstance(config, dict):
        raise ValueError("Config must be a JSON object")
    return config


def settings_from_config(config: dict[str, Any]) -> Settings:
    resolvers = tuple(str(x) for x in config.get("resolvers", []))
    if not resolvers:
        raise ValueError("At least one resolver is required")

    for resolver in resolvers:
        try:
            ipaddress.ip_address(resolver)
        except ValueError as exc:
            raise ValueError(f"Resolver must be an IP address: {resolver}") from exc

    settings = Settings(
        resolvers=resolvers,
        timeout_seconds=float(config.get("timeout_seconds", 2.0)),
        lifetime_seconds=float(config.get("lifetime_seconds", 4.0)),
        negative_votes_required=int(config.get("negative_votes_required", math.ceil(len(resolvers) / 2))),
        suspect_after_failures=int(config.get("suspect_after_failures", 3)),
        quarantine_after_failures=int(config.get("quarantine_after_failures", 7)),
        expire_after_days=int(config.get("expire_after_days", 30)),
        max_workers=int(config.get("max_workers", 20)),
    )

    if not (1 <= settings.negative_votes_required <= len(resolvers)):
        raise ValueError("negative_votes_required must be between 1 and the resolver count")
    if settings.suspect_after_failures < 1:
        raise ValueError("suspect_after_failures must be >= 1")
    if settings.quarantine_after_failures < settings.suspect_after_failures:
        raise ValueError("quarantine_after_failures must be >= suspect_after_failures")
    if settings.expire_after_days < 1:
        raise ValueError("expire_after_days must be >= 1")
    if settings.max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    return settings


def query_one_resolver(host: str, nameserver: str, settings: Settings) -> dict[str, Any]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = settings.timeout_seconds
    resolver.lifetime = settings.lifetime_seconds
    resolver.retry_servfail = True

    try:
        answer = resolver.resolve(host, "A", search=False)
        addresses = sorted({r.address for r in answer})
        return {
            "status": "OK",
            "ipv4": addresses,
            "canonical_name": str(answer.canonical_name).rstrip(".").lower(),
        }
    except dns.resolver.NXDOMAIN:
        return {"status": "NXDOMAIN", "ipv4": []}
    except dns.resolver.NoAnswer:
        return {"status": "NO_A", "ipv4": []}
    except dns.resolver.NoNameservers as exc:
        return {"status": "NO_NAMESERVERS", "ipv4": [], "detail": str(exc)[:300]}
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
        return {"status": "TIMEOUT", "ipv4": [], "detail": str(exc)[:300]}
    except dns.exception.DNSException as exc:
        return {"status": "DNS_ERROR", "ipv4": [], "detail": f"{type(exc).__name__}: {exc}"[:300]}
    except Exception as exc:  # Defensive boundary for unattended CI execution.
        return {"status": "ERROR", "ipv4": [], "detail": f"{type(exc).__name__}: {exc}"[:300]}


def check_host(host: str, settings: Settings) -> DNSResult:
    resolver_results: dict[str, dict[str, Any]] = {}
    for nameserver in settings.resolvers:
        resolver_results[nameserver] = query_one_resolver(host, nameserver, settings)
    return aggregate_resolver_results(resolver_results, settings.negative_votes_required)


def validate_collection_config(collection: dict[str, Any]) -> None:
    required = {"name", "active", "manual", "discovered", "pending", "suspect", "quarantine", "expired", "state"}
    missing = sorted(required - set(collection))
    if missing:
        raise ValueError(f"Collection {collection.get('name', '<unnamed>')} missing keys: {', '.join(missing)}")


def resolve_collection_paths(repo_root: Path, collection: dict[str, Any]) -> dict[str, Path]:
    return {
        key: (repo_root / str(collection[key])).resolve()
        for key in ("active", "manual", "discovered", "pending", "suspect", "quarantine", "expired", "state")
    }


def ensure_paths_inside_repo(repo_root: Path, paths: dict[str, Path]) -> None:
    root = repo_root.resolve()
    for name, path in paths.items():
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Collection path {name} escapes repository root: {path}") from exc


def maintain_collection(
    repo_root: Path,
    collection: dict[str, Any],
    settings: Settings,
    now: datetime,
    dry_run: bool,
) -> dict[str, int]:
    validate_collection_config(collection)
    name = str(collection["name"])
    paths = resolve_collection_paths(repo_root, collection)
    ensure_paths_inside_repo(repo_root, paths)

    state = load_json(paths["state"], {"version": STATE_VERSION, "updated_at": None, "hosts": {}})
    if not isinstance(state, dict) or not isinstance(state.get("hosts"), dict):
        raise ValueError(f"Invalid state file for collection {name}: {paths['state']}")
    if int(state.get("version", STATE_VERSION)) != STATE_VERSION:
        raise ValueError(f"Unsupported state version in {paths['state']}")

    hosts: dict[str, dict[str, Any]] = state["hosts"]

    legacy_active = read_host_file(paths["active"])
    manual_queue = read_host_file(paths["manual"])
    discovered_queue = read_host_file(paths["discovered"])

    imported = 0
    requeued = 0

    # Existing active.txt is treated as a migration/bootstrap source only for names
    # that are not yet represented in state.json.
    for host in sorted(legacy_active):
        if host not in hosts:
            hosts[host] = new_host_state(host, now, "legacy_active", legacy_active=True)
            imported += 1

    for source, queue in (("manual", manual_queue), ("discovered", discovered_queue)):
        for host in sorted(queue):
            if host not in hosts:
                hosts[host] = new_host_state(host, now, source, legacy_active=False)
                imported += 1
            elif hosts[host].get("status") == "expired":
                revive_expired(hosts[host], now, source)
                requeued += 1
            else:
                add_source(hosts[host], source)

    targets = sorted(host for host, item in hosts.items() if item.get("status") != "expired")
    print(f"[{name}] checking {len(targets)} host(s) with {len(settings.resolvers)} resolver(s)")

    results: dict[str, DNSResult] = {}
    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(settings.max_workers, len(targets))) as pool:
            future_map = {pool.submit(check_host, host, settings): host for host in targets}
            for future in concurrent.futures.as_completed(future_map):
                host = future_map[future]
                try:
                    results[host] = future.result()
                except Exception as exc:
                    print(f"ERROR [{name}] unexpected worker failure for {host}: {exc}", file=sys.stderr)
                    results[host] = DNSResult("TRANSIENT", tuple(), None, {"internal": {"status": "ERROR", "detail": str(exc)[:300]}})

    transitions: dict[str, int] = {}
    aggregate_counts = {"OK": 0, "NEGATIVE": 0, "TRANSIENT": 0}

    for host in targets:
        result = results[host]
        aggregate_counts[result.aggregate] += 1
        old_status, new_status = apply_check_result(hosts[host], result, now, settings)
        if old_status != new_status:
            key = f"{old_status}->{new_status}"
            transitions[key] = transitions.get(key, 0) + 1
            print(f"[{name}] {host}: {old_status} -> {new_status}")

    active_hosts = {
        host
        for host, item in hosts.items()
        if item.get("status") in {"active", "suspect"} and item.get("ever_validated")
    }
    pending_hosts = {host for host, item in hosts.items() if item.get("status") == "pending"}
    suspect_hosts = {host for host, item in hosts.items() if item.get("status") == "suspect"}
    quarantine_hosts = {host for host, item in hosts.items() if item.get("status") == "quarantine"}
    expired_hosts = {host for host, item in hosts.items() if item.get("status") == "expired"}

    state["version"] = STATE_VERSION
    state["updated_at"] = iso(now)
    state["hosts"] = dict(sorted(hosts.items()))

    if not dry_run:
        write_host_file(paths["active"], active_hosts)
        write_host_file(paths["pending"], pending_hosts)
        write_host_file(paths["suspect"], suspect_hosts)
        write_host_file(paths["quarantine"], quarantine_hosts)
        write_host_file(paths["expired"], expired_hosts)
        save_json(paths["state"], state)
        # Queue semantics: once imported into state.json, these files are cleared.
        write_host_file(paths["manual"], [])
        write_host_file(paths["discovered"], [])

    print(
        f"[{name}] OK={aggregate_counts['OK']} NEGATIVE={aggregate_counts['NEGATIVE']} "
        f"TRANSIENT={aggregate_counts['TRANSIENT']} | active={len(active_hosts)} pending={len(pending_hosts)} "
        f"suspect={len(suspect_hosts)} quarantine={len(quarantine_hosts)} expired={len(expired_hosts)}"
    )

    return {
        "checked": len(targets),
        "imported": imported,
        "requeued": requeued,
        "ok": aggregate_counts["OK"],
        "negative": aggregate_counts["NEGATIVE"],
        "transient": aggregate_counts["TRANSIENT"],
        "active": len(active_hosts),
        "pending": len(pending_hosts),
        "suspect": len(suspect_hosts),
        "quarantine": len(quarantine_hosts),
        "expired": len(expired_hosts),
        "transitions": sum(transitions.values()),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Maintain DNS hostname lists")
    parser.add_argument("--config", default="dns_maintenance/config.json", help="Path to JSON config, relative to repo root")
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--collection", action="append", help="Run only the named collection; may be repeated")
    parser.add_argument("--dry-run", action="store_true", help="Check and print results without writing files")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo_root = Path(args.repo_root).resolve()
    config_path = (repo_root / args.config).resolve()

    try:
        config_path.relative_to(repo_root)
    except ValueError:
        print("ERROR: config path must be inside repository root", file=sys.stderr)
        return 2

    try:
        config = load_config(config_path)
        settings = settings_from_config(config)
        collections = config.get("collections", [])
        if not isinstance(collections, list) or not collections:
            raise ValueError("Config must contain a non-empty collections array")

        selected = set(args.collection or [])
        if selected:
            available = {str(c.get("name")) for c in collections if isinstance(c, dict)}
            unknown = selected - available
            if unknown:
                raise ValueError(f"Unknown collection(s): {', '.join(sorted(unknown))}")
            collections = [c for c in collections if str(c.get("name")) in selected]

        now = utc_now()
        totals: dict[str, int] = {}
        for collection in collections:
            if not isinstance(collection, dict):
                raise ValueError("Each collection must be an object")
            stats = maintain_collection(repo_root, collection, settings, now, args.dry_run)
            for key, value in stats.items():
                totals[key] = totals.get(key, 0) + int(value)

        mode = "DRY RUN" if args.dry_run else "DONE"
        print(
            f"{mode}: checked={totals.get('checked', 0)}, imported={totals.get('imported', 0)}, "
            f"active={totals.get('active', 0)}, pending={totals.get('pending', 0)}, suspect={totals.get('suspect', 0)}, "
            f"quarantine={totals.get('quarantine', 0)}, expired={totals.get('expired', 0)}"
        )
        return 0
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
