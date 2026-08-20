#!/usr/bin/env python3
"""Generate a compact Markdown observability report for DNS maintenance."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def read_hosts(path: Path) -> list[str]:
    if not path.exists():
        return []
    result: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        host = line.strip().lower().rstrip(".")
        if host and not host.startswith("#") and host not in seen:
            result.append(host)
            seen.add(host)
    return result


def safe_path(repo_root: Path, raw: str) -> Path:
    path = (repo_root / raw).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {path}") from exc
    return path


def pct(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.1f}%"


def esc(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def failure_type(entry: dict[str, Any]) -> str:
    failure = entry.get("last_failure")
    if isinstance(failure, dict):
        return str(failure.get("type") or "UNKNOWN")
    if isinstance(failure, str) and failure:
        return "LEGACY"
    return "-"


def render_report(
    name: str,
    collection: dict[str, Any],
    dns_state: dict[str, Any],
    service_state: dict[str, Any],
    discovery_state: dict[str, Any],
    active_hosts: list[str],
    generated_at: datetime,
) -> str:
    dns_hosts = dns_state.get("hosts", {}) if isinstance(dns_state.get("hosts"), dict) else {}
    service_hosts = service_state.get("hosts", {}) if isinstance(service_state.get("hosts"), dict) else {}
    active_set = set(active_hosts)

    dns_counts = Counter(
        str(item.get("status", "unknown"))
        for item in dns_hosts.values()
        if isinstance(item, dict)
    )
    service_counts = Counter(
        str(service_hosts.get(host, {}).get("status", "unknown"))
        for host in active_hosts
    )
    last_results = Counter(
        str(service_hosts.get(host, {}).get("last_result", "UNTESTED"))
        for host in active_hosts
    )

    current_failures: Counter[str] = Counter()
    failure_rows: list[tuple[str, dict[str, Any]]] = []
    for host in active_hosts:
        entry = service_hosts.get(host, {})
        if not isinstance(entry, dict):
            continue
        if entry.get("last_result") == "FAILURE" or entry.get("status") in {"suspect", "dead"}:
            current_failures[failure_type(entry)] += 1
            failure_rows.append((host, entry))

    stable_100 = 0
    stable_80 = 0
    stable_low = 0
    stable_na = 0
    for host in active_hosts:
        score = service_hosts.get(host, {}).get("stability_score")
        if score is None:
            stable_na += 1
        elif float(score) >= 100.0:
            stable_100 += 1
        elif float(score) >= 80.0:
            stable_80 += 1
        else:
            stable_low += 1

    dns_updated = str(dns_state.get("updated_at") or "-")
    service_updated = str(service_state.get("updated_at") or "-")
    discovery_updated = str(discovery_state.get("updated_at") or "-")

    # update_dns.py gives all imported hosts in one run the same first_seen as
    # state.updated_at, so this is a reliable run-local approximation without
    # adding temporary files or a second persistence layer.
    new_discovered: list[dict[str, Any]] = []
    if dns_state.get("updated_at"):
        for item in dns_hosts.values():
            if not isinstance(item, dict):
                continue
            sources = item.get("sources", [])
            if item.get("first_seen") == dns_state.get("updated_at") and isinstance(sources, list) and "discovered" in sources:
                new_discovered.append(item)
    new_discovered_counts = Counter(str(item.get("status", "unknown")) for item in new_discovered)

    lines: list[str] = [
        f"# {name.title()} DNS Maintenance Report",
        "",
        f"> Generated automatically at `{iso(generated_at)}`. HTTPS/TLS health is observational and does **not** remove entries from the public DNS list.",
        "",
        "## Overview",
        "",
        "| Layer | Metric | Count |",
        "|---|---|---:|",
        f"| DNS | Active | {dns_counts.get('active', 0)} |",
        f"| DNS | Pending | {dns_counts.get('pending', 0)} |",
        f"| DNS | Suspect | {dns_counts.get('suspect', 0)} |",
        f"| DNS | Quarantine | {dns_counts.get('quarantine', 0)} |",
        f"| DNS | Expired | {dns_counts.get('expired', 0)} |",
        f"| HTTPS/TLS | Alive | {service_counts.get('alive', 0)} |",
        f"| HTTPS/TLS | Unknown | {service_counts.get('unknown', 0)} |",
        f"| HTTPS/TLS | Suspect | {service_counts.get('suspect', 0)} |",
        f"| HTTPS/TLS | Dead | {service_counts.get('dead', 0)} |",
        "",
        "## Latest HTTPS/TLS check",
        "",
        f"State updated: `{service_updated}`",
        "",
        "| Result | Count |",
        "|---|---:|",
        f"| ALIVE | {last_results.get('ALIVE', 0)} |",
        f"| FAILURE | {last_results.get('FAILURE', 0)} |",
        f"| SKIPPED | {last_results.get('SKIPPED', 0)} |",
        f"| UNTESTED/other | {sum(v for k, v in last_results.items() if k not in {'ALIVE','FAILURE','SKIPPED'})} |",
        "",
        "## Stability window",
        "",
        "`stability_score` is the percentage of successful HTTPS/TLS checks among the last measured checks. `SKIPPED` checks are excluded. The history window is capped by `service_check.history_limit`.",
        "",
        "| Score | Hosts |",
        "|---|---:|",
        f"| 100% | {stable_100} |",
        f"| 80-99.9% | {stable_80} |",
        f"| <80% | {stable_low} |",
        f"| n/a | {stable_na} |",
    ]

    lines += ["", "## Current failures", ""]
    if current_failures:
        lines += ["| Type | Hosts |", "|---|---:|"]
        for key in sorted(current_failures):
            lines.append(f"| {esc(key)} | {current_failures[key]} |")
    else:
        lines.append("No current HTTPS/TLS failures.")

    if failure_rows:
        lines += [
            "",
            "### Failure details",
            "",
            "| Hostname | State | Consecutive failures | Last error | IPv4 | Stability | Samples | Last check |",
            "|---|---|---:|---|---|---:|---:|---|",
        ]
        for host, entry in sorted(
            failure_rows,
            key=lambda pair: (-int(pair[1].get("consecutive_failures", 0)), pair[0]),
        ):
            ips = ", ".join(str(x) for x in entry.get("last_ipv4", [])) or "-"
            lines.append(
                f"| `{esc(host)}` | {esc(entry.get('status', 'unknown'))} | "
                f"{int(entry.get('consecutive_failures', 0))} | {esc(failure_type(entry))} | "
                f"{esc(ips)} | {pct(entry.get('stability_score'))} | "
                f"{int(entry.get('history_samples', 0))} | `{esc(entry.get('last_check') or '-')}` |"
            )

    lines += [
        "",
        "## Discovery",
        "",
        f"Discovery state updated: `{discovery_updated}`  ",
        f"DNS state updated: `{dns_updated}`",
        "",
        f"New CT-discovered hosts imported in the latest DNS-maintenance run: **{len(new_discovered)}**.",
    ]
    if new_discovered:
        lines += [
            "",
            "| Resulting DNS state | Count |",
            "|---|---:|",
        ]
        for key in sorted(new_discovered_counts):
            lines.append(f"| {esc(key)} | {new_discovered_counts[key]} |")

    certspotter = discovery_state.get("sources", {}).get("certspotter", {}) if isinstance(discovery_state.get("sources"), dict) else {}
    if isinstance(certspotter, dict) and certspotter:
        lines += [
            "",
            "### Certificate Transparency cursors",
            "",
            "| Root domain | Caught up | Last poll |",
            "|---|---|---|",
        ]
        for domain in sorted(certspotter):
            item = certspotter.get(domain, {})
            if not isinstance(item, dict):
                item = {}
            lines.append(
                f"| `{esc(domain)}` | {'yes' if item.get('caught_up') else 'no'} | `{esc(item.get('last_poll') or '-')}` |"
            )

    lines += [
        "",
        "## Notes",
        "",
        f"- Public active DNS file: `{collection.get('active', '-')}` ({len(active_set)} hostnames).",
        "- HTTPS/TLS health is a separate signal. A host may be a valid DNS/service endpoint even when TCP/443 or ordinary HTTPS is not applicable.",
        "- DNS lifecycle rules remain unchanged by this report.",
        "",
    ]
    return "\n".join(lines)


def generate_collection(repo_root: Path, collection: dict[str, Any], dry_run: bool) -> Path | None:
    name = str(collection.get("name", "unnamed"))
    service_cfg = collection.get("service_check", {})
    if not isinstance(service_cfg, dict) or not service_cfg.get("enabled", False):
        print(f"[{name}] report skipped: service check disabled")
        return None

    active_path = safe_path(repo_root, str(collection["active"]))
    dns_state_path = safe_path(repo_root, str(collection["state"]))
    service_state_path = safe_path(repo_root, str(service_cfg.get("state", f"dns/{name}/service_state.json")))
    discovery_cfg = collection.get("discovery", {}) if isinstance(collection.get("discovery"), dict) else {}
    discovery_state_path = safe_path(repo_root, str(discovery_cfg.get("state", f"dns/{name}/discovery_state.json")))
    report_path = safe_path(repo_root, str(service_cfg.get("report", f"dns/{name}/report.md")))

    dns_state = load_json(dns_state_path, {"hosts": {}})
    service_state = load_json(service_state_path, {"hosts": {}})
    discovery_state = load_json(discovery_state_path, {"sources": {}})
    if not all(isinstance(x, dict) for x in (dns_state, service_state, discovery_state)):
        raise ValueError(f"[{name}] one or more state files are not JSON objects")

    report = render_report(
        name,
        collection,
        dns_state,
        service_state,
        discovery_state,
        read_hosts(active_path),
        utc_now(),
    )
    if dry_run:
        print(report)
    else:
        atomic_write_text(report_path, report)
        print(f"[{name}] report written: {report_path.relative_to(repo_root)}")
    return report_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate DNS maintenance Markdown report")
    parser.add_argument("--config", default="dns_maintenance/config.json")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--collection", action="append")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo_root = Path(args.repo_root).resolve()
    config_path = safe_path(repo_root, args.config)
    try:
        config = load_json(config_path, None)
        if not isinstance(config, dict):
            raise ValueError("Config must be a JSON object")
        collections = config.get("collections", [])
        if not isinstance(collections, list) or not collections:
            raise ValueError("Config must contain a non-empty collections array")
        selected = set(args.collection or [])
        if selected:
            collections = [c for c in collections if isinstance(c, dict) and str(c.get("name")) in selected]
            if not collections:
                raise ValueError("No selected collection found")
        for collection in collections:
            if not isinstance(collection, dict):
                raise ValueError("Each collection must be an object")
            generate_collection(repo_root, collection, args.dry_run)
        return 0
    except (ValueError, KeyError, json.JSONDecodeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
