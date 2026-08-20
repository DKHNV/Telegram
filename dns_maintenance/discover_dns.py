#!/usr/bin/env python3
"""Discover candidate DNS names from Certificate Transparency data.

This script deliberately only *discovers candidates*. It never places a hostname
straight into the public active list. Candidates are written to discovered.txt,
and update_dns.py performs the normal multi-resolver validation and lifecycle.

The first Cert Spotter runs may walk older unexpired certificate history in small
batches. The cursor is persisted in discovery_state.json, so subsequent scheduled
runs continue where the previous run stopped and eventually become incremental.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    from dns_maintenance.update_dns import (
        atomic_write_text,
        load_config,
        load_json,
        normalize_hostname,
        read_host_file,
    )
except ModuleNotFoundError:  # Allows: python dns_maintenance/discover_dns.py
    from update_dns import (
        atomic_write_text,
        load_config,
        load_json,
        normalize_hostname,
        read_host_file,
    )

DISCOVERY_STATE_VERSION = 1
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def save_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def write_host_file(path: Path, hosts: set[str]) -> None:
    content = "".join(f"{host}\n" for host in sorted(hosts))
    atomic_write_text(path, content)


def is_within_root(host: str, root: str) -> bool:
    host = host.lower().rstrip(".")
    root = root.lower().rstrip(".")
    return host == root or host.endswith("." + root)


def extract_candidates(issuances: list[dict[str, Any]], root: str) -> set[str]:
    """Extract concrete hostnames from Cert Spotter issuance objects.

    Wildcard SANs are skipped. A certificate for *.example.org proves a wildcard
    exists, but does not reveal a concrete hostname worth feeding to the scanner.
    """
    result: set[str] = set()
    for issuance in issuances:
        dns_names = issuance.get("dns_names", [])
        if not isinstance(dns_names, list):
            continue
        for raw in dns_names:
            if not isinstance(raw, str):
                continue
            value = raw.strip().lower()
            if value.startswith("*."):
                continue
            host = normalize_hostname(value)
            if host and is_within_root(host, root):
                result.add(host)
    return result


def fetch_certspotter_page(
    domain: str,
    after: int | None,
    timeout_seconds: float,
    user_agent: str,
) -> tuple[list[dict[str, Any]], int | None]:
    params: list[tuple[str, str]] = [
        ("domain", domain),
        ("include_subdomains", "true"),
        ("expand", "dns_names"),
    ]
    if after is not None:
        params.append(("after", str(after)))

    url = CERTSPOTTER_URL + "?" + urlencode(params)
    headers = {
        "Accept": "application/json",
        "User-Agent": user_agent,
    }
    api_key = os.environ.get("CERTSPOTTER_API_KEY", "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = Request(url, headers=headers, method="GET")
    with urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if not isinstance(payload, list):
        raise ValueError("Cert Spotter returned a non-array JSON response")

    page: list[dict[str, Any]] = [item for item in payload if isinstance(item, dict)]
    next_after: int | None = after
    if page:
        raw_id = page[-1].get("id")
        if raw_id is not None:
            next_after = int(raw_id)
    return page, next_after


def known_hosts(repo_root: Path, collection: dict[str, Any]) -> set[str]:
    known: set[str] = set()
    for key in ("active", "manual", "discovered", "pending", "suspect", "quarantine", "expired"):
        raw_path = collection.get(key)
        if raw_path:
            known.update(read_host_file((repo_root / str(raw_path)).resolve()))

    state_path = collection.get("state")
    if state_path:
        state = load_json((repo_root / str(state_path)).resolve(), {"hosts": {}})
        if isinstance(state, dict) and isinstance(state.get("hosts"), dict):
            known.update(str(host) for host in state["hosts"].keys())
    return known


def discover_collection(
    repo_root: Path,
    collection: dict[str, Any],
    dry_run: bool,
) -> dict[str, int]:
    name = str(collection.get("name", "<unnamed>"))
    discovery = collection.get("discovery", {})
    if not isinstance(discovery, dict) or not discovery.get("enabled", False):
        print(f"[{name}] discovery disabled")
        return {"candidates": 0, "new": 0, "requests": 0, "errors": 0}

    certspotter = discovery.get("certspotter", {})
    if not isinstance(certspotter, dict):
        raise ValueError(f"[{name}] discovery.certspotter must be an object")

    domains_raw = certspotter.get("domains", [])
    if not isinstance(domains_raw, list) or not domains_raw:
        raise ValueError(f"[{name}] discovery.certspotter.domains must be a non-empty array")

    domains: list[str] = []
    for raw in domains_raw:
        domain = normalize_hostname(str(raw))
        if not domain:
            raise ValueError(f"[{name}] invalid discovery domain: {raw!r}")
        domains.append(domain)
    domains = sorted(set(domains))

    state_rel = str(discovery.get("state", f"dns/{name}/discovery_state.json"))
    state_path = (repo_root / state_rel).resolve()
    discovered_path = (repo_root / str(collection["discovered"])).resolve()
    root = repo_root.resolve()
    for path in (state_path, discovered_path):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"[{name}] discovery path escapes repository root: {path}") from exc

    state = load_json(
        state_path,
        {
            "version": DISCOVERY_STATE_VERSION,
            "updated_at": None,
            "sources": {"certspotter": {}},
        },
    )
    if not isinstance(state, dict):
        raise ValueError(f"[{name}] invalid discovery state")
    if int(state.get("version", DISCOVERY_STATE_VERSION)) != DISCOVERY_STATE_VERSION:
        raise ValueError(f"[{name}] unsupported discovery state version")
    state.setdefault("sources", {}).setdefault("certspotter", {})

    max_pages = int(certspotter.get("max_pages_per_domain", 5))
    if max_pages < 1 or max_pages > 100:
        raise ValueError(f"[{name}] max_pages_per_domain must be between 1 and 100")
    timeout_seconds = float(certspotter.get("request_timeout_seconds", 30.0))
    user_agent = str(certspotter.get("user_agent", "DKHNV-DNS-Maintenance/1.0"))

    existing_queue = read_host_file(discovered_path)
    known = known_hosts(repo_root, collection)
    all_candidates: set[str] = set()
    requests = 0
    errors = 0

    for domain in domains:
        domain_state = state["sources"]["certspotter"].setdefault(
            domain,
            {"after": None, "caught_up": False, "last_poll": None},
        )
        after_raw = domain_state.get("after")
        after = int(after_raw) if after_raw is not None else None
        domain_candidates: set[str] = set()
        caught_up = False

        for _ in range(max_pages):
            try:
                page, next_after = fetch_certspotter_page(domain, after, timeout_seconds, user_agent)
                requests += 1
            except HTTPError as exc:
                errors += 1
                detail = f"HTTP {exc.code}"
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                if retry_after:
                    detail += f", Retry-After={retry_after}s"
                print(f"WARN [{name}] Cert Spotter {domain}: {detail}; keeping previous cursor", file=sys.stderr)
                break
            except (URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as exc:
                errors += 1
                print(f"WARN [{name}] Cert Spotter {domain}: {type(exc).__name__}: {exc}", file=sys.stderr)
                break

            if not page:
                caught_up = True
                break

            domain_candidates.update(extract_candidates(page, domain))
            if next_after == after:
                print(f"WARN [{name}] Cert Spotter {domain}: cursor did not advance; stopping", file=sys.stderr)
                break
            after = next_after

        all_candidates.update(domain_candidates)
        if not dry_run:
            domain_state["after"] = after
            domain_state["caught_up"] = caught_up
            domain_state["last_poll"] = iso_now()

        mode = "caught up" if caught_up else f"batch limit {max_pages}"
        print(f"[{name}] CT {domain}: found {len(domain_candidates)} concrete hostname(s), {mode}")

    new_candidates = all_candidates - known
    merged_queue = existing_queue | new_candidates

    print(
        f"[{name}] discovery: candidates={len(all_candidates)} new={len(new_candidates)} "
        f"already_known={len(all_candidates - new_candidates)} requests={requests} errors={errors}"
    )
    if new_candidates:
        preview = sorted(new_candidates)[:25]
        for host in preview:
            print(f"[{name}] discovered: {host}")
        if len(new_candidates) > len(preview):
            print(f"[{name}] ... and {len(new_candidates) - len(preview)} more")

    if not dry_run:
        write_host_file(discovered_path, merged_queue)
        state["version"] = DISCOVERY_STATE_VERSION
        state["updated_at"] = iso_now()
        save_json(state_path, state)

    return {
        "candidates": len(all_candidates),
        "new": len(new_candidates),
        "requests": requests,
        "errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discover candidate DNS names from Certificate Transparency")
    parser.add_argument("--config", default="dns_maintenance/config.json", help="Path to JSON config relative to repo root")
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--collection", action="append", help="Run only the named collection; may be repeated")
    parser.add_argument("--dry-run", action="store_true", help="Print candidates without writing queue or cursor state")
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

        totals = {"candidates": 0, "new": 0, "requests": 0, "errors": 0}
        for collection in collections:
            if not isinstance(collection, dict):
                raise ValueError("Each collection must be an object")
            stats = discover_collection(repo_root, collection, args.dry_run)
            for key in totals:
                totals[key] += int(stats.get(key, 0))

        mode = "DISCOVERY DRY RUN" if args.dry_run else "DISCOVERY DONE"
        print(
            f"{mode}: candidates={totals['candidates']}, new={totals['new']}, "
            f"requests={totals['requests']}, errors={totals['errors']}"
        )
        return 0
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
