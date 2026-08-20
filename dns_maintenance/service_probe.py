#!/usr/bin/env python3
"""Probe HTTPS/TLS reachability for DNS names maintained by update_dns.py.

This checker is intentionally observational: it never removes hosts from the
main DNS list. It writes independent service-health state and summary files.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import copy
import json
import os
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SERVICE_STATE_VERSION = 1
HTTP_STATUS_RE = re.compile(rb"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def write_host_file(path: Path, hosts: Iterable[str]) -> None:
    content = "".join(f"{host}\n" for host in sorted(set(hosts)))
    atomic_write_text(path, content)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def read_hosts(path: Path) -> list[str]:
    if not path.exists():
        return []
    hosts: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        host = line.strip().lower().rstrip(".")
        if not host or host.startswith("#") or host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def parse_http_status(data: bytes) -> int | None:
    first_line = data.split(b"\r\n", 1)[0].strip()
    match = HTTP_STATUS_RE.match(first_line)
    if not match:
        return None
    return int(match.group(1))


def aggregate_attempts(attempts: list[dict[str, Any]]) -> str:
    if any(a.get("status") in {"HTTPS_OK", "TLS_OK"} for a in attempts):
        return "ALIVE"
    if not attempts:
        return "SKIPPED"
    return "FAILURE"


def new_service_state(host: str, now: datetime) -> dict[str, Any]:
    return {
        "hostname": host,
        "status": "unknown",
        "first_seen": iso(now),
        "last_check": None,
        "last_success": None,
        "last_failure": None,
        "last_result": "UNTESTED",
        "consecutive_failures": 0,
        "ever_alive": False,
        "last_ipv4": [],
        "attempts": [],
    }


def apply_service_result(
    state: dict[str, Any],
    aggregate: str,
    attempts: list[dict[str, Any]],
    ipv4: list[str],
    now: datetime,
    suspect_after_failures: int,
    dead_after_failures: int,
) -> tuple[str, str]:
    old = str(state.get("status", "unknown"))
    stamp = iso(now)
    state["last_check"] = stamp
    state["attempts"] = attempts
    state["last_ipv4"] = list(ipv4)
    state["last_result"] = aggregate

    if aggregate == "ALIVE":
        state["status"] = "alive"
        state["last_success"] = stamp
        state["consecutive_failures"] = 0
        state["ever_alive"] = True
        return old, "alive"

    if aggregate == "SKIPPED":
        # No current IPv4 means DNS validation could not provide a safe target.
        # Do not punish service health for a DNS-layer problem.
        return old, old

    state["last_failure"] = stamp
    failures = int(state.get("consecutive_failures", 0)) + 1
    state["consecutive_failures"] = failures

    if failures >= dead_after_failures:
        state["status"] = "dead"
    elif failures >= suspect_after_failures:
        state["status"] = "suspect"
    else:
        state["status"] = "alive" if state.get("ever_alive") else "unknown"

    return old, str(state["status"])


def probe_ip(
    host: str,
    ip: str,
    port: int,
    path: str,
    timeout_seconds: float,
    user_agent: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {"ip": ip, "port": port, "status": "ERROR"}
    raw_sock: socket.socket | None = None
    tls_sock: ssl.SSLSocket | None = None

    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout_seconds)
        raw_sock.settimeout(timeout_seconds)

        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
        raw_sock = None  # ownership transferred to tls_sock

        result["tls_version"] = tls_sock.version()
        cipher = tls_sock.cipher()
        if cipher:
            result["cipher"] = cipher[0]

        request = (
            f"HEAD {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="strict")
        tls_sock.sendall(request)

        try:
            data = tls_sock.recv(4096)
        except (socket.timeout, TimeoutError):
            # A verified TLS handshake is already enough to establish that a
            # TLS service for this hostname is alive, even if HTTP is silent.
            result["status"] = "TLS_OK"
            result["detail"] = "verified TLS handshake; HTTP response timeout"
            return result

        status_code = parse_http_status(data)
        if status_code is not None:
            result["status"] = "HTTPS_OK"
            result["http_status"] = status_code
        else:
            result["status"] = "TLS_OK"
            result["detail"] = "verified TLS handshake; non-HTTP or empty response"
        return result

    except ssl.SSLCertVerificationError as exc:
        result["status"] = "TLS_CERT_ERROR"
        result["detail"] = str(exc)[:300]
    except ssl.SSLError as exc:
        result["status"] = "TLS_ERROR"
        result["detail"] = str(exc)[:300]
    except (socket.timeout, TimeoutError):
        result["status"] = "TIMEOUT"
    except ConnectionRefusedError:
        result["status"] = "REFUSED"
    except OSError as exc:
        result["status"] = "NETWORK_ERROR"
        result["detail"] = f"{type(exc).__name__}: {exc}"[:300]
    except Exception as exc:  # Defensive: one broken target must not kill the job.
        result["status"] = "ERROR"
        result["detail"] = f"{type(exc).__name__}: {exc}"[:300]
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        if raw_sock is not None:
            try:
                raw_sock.close()
            except OSError:
                pass

    return result


def probe_host(
    host: str,
    ipv4: list[str],
    settings: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], list[str]]:
    max_ips = int(settings.get("max_ipv4_per_host", 3))
    selected = list(dict.fromkeys(ipv4))[:max_ips]
    if not selected:
        return "SKIPPED", [], []

    port = int(settings.get("port", 443))
    path = str(settings.get("path", "/")) or "/"
    if not path.startswith("/"):
        path = "/" + path
    timeout_seconds = float(settings.get("timeout_seconds", 4.0))
    user_agent = str(settings.get("user_agent", "DKHNV-DNS-Maintenance/1.0"))

    attempts: list[dict[str, Any]] = []
    for ip in selected:
        attempt = probe_ip(host, ip, port, path, timeout_seconds, user_agent)
        attempts.append(attempt)
        if attempt.get("status") in {"HTTPS_OK", "TLS_OK"}:
            break

    return aggregate_attempts(attempts), attempts, selected


def validate_service_config(cfg: dict[str, Any]) -> None:
    if int(cfg.get("port", 443)) < 1 or int(cfg.get("port", 443)) > 65535:
        raise ValueError("service_check.port must be between 1 and 65535")
    if float(cfg.get("timeout_seconds", 4.0)) <= 0:
        raise ValueError("service_check.timeout_seconds must be > 0")
    if int(cfg.get("max_workers", 10)) < 1:
        raise ValueError("service_check.max_workers must be >= 1")
    if int(cfg.get("max_ipv4_per_host", 3)) < 1:
        raise ValueError("service_check.max_ipv4_per_host must be >= 1")
    suspect = int(cfg.get("suspect_after_failures", 3))
    dead = int(cfg.get("dead_after_failures", 7))
    if suspect < 1 or dead < suspect:
        raise ValueError("service_check failure thresholds are invalid")


def service_collection(repo_root: Path, collection: dict[str, Any], dry_run: bool) -> dict[str, int]:
    name = str(collection.get("name", "unnamed"))
    service_cfg = collection.get("service_check", {})
    if not isinstance(service_cfg, dict) or not service_cfg.get("enabled", False):
        print(f"[{name}] service check disabled")
        return {"checked": 0, "alive": 0, "suspect": 0, "dead": 0, "unknown": 0}

    validate_service_config(service_cfg)

    def p(key: str, default: str | None = None) -> Path:
        value = service_cfg.get(key, default)
        if not value:
            raise ValueError(f"[{name}] missing service_check.{key}")
        path = (repo_root / str(value)).resolve()
        try:
            path.relative_to(repo_root)
        except ValueError as exc:
            raise ValueError(f"[{name}] path escapes repository: {path}") from exc
        return path

    active_path = (repo_root / str(collection["active"])).resolve()
    dns_state_path = (repo_root / str(collection["state"])).resolve()
    service_state_path = p("state", f"dns/{name}/service_state.json")
    alive_path = p("alive", f"dns/{name}/service_alive.txt")
    suspect_path = p("suspect", f"dns/{name}/service_suspect.txt")
    dead_path = p("dead", f"dns/{name}/service_dead.txt")
    unknown_path = p("unknown", f"dns/{name}/service_unknown.txt")

    active_hosts = read_hosts(active_path)
    dns_state = load_json(dns_state_path, {"hosts": {}})
    dns_hosts = dns_state.get("hosts", {}) if isinstance(dns_state, dict) else {}
    if not isinstance(dns_hosts, dict):
        dns_hosts = {}

    service_state = load_json(
        service_state_path,
        {"version": SERVICE_STATE_VERSION, "updated_at": None, "hosts": {}},
    )
    if not isinstance(service_state, dict):
        raise ValueError(f"[{name}] invalid service state")
    if int(service_state.get("version", SERVICE_STATE_VERSION)) != SERVICE_STATE_VERSION:
        raise ValueError(f"[{name}] unsupported service state version")
    service_hosts = service_state.setdefault("hosts", {})
    if not isinstance(service_hosts, dict):
        raise ValueError(f"[{name}] invalid service hosts state")

    now = utc_now()
    for host in active_hosts:
        service_hosts.setdefault(host, new_service_state(host, now))

    max_workers = int(service_cfg.get("max_workers", 10))
    suspect_after = int(service_cfg.get("suspect_after_failures", 3))
    dead_after = int(service_cfg.get("dead_after_failures", 7))

    results: dict[str, tuple[str, list[dict[str, Any]], list[str]]] = {}

    def work(host: str) -> tuple[str, tuple[str, list[dict[str, Any]], list[str]]]:
        dns_record = dns_hosts.get(host, {})
        ipv4 = dns_record.get("ipv4", []) if isinstance(dns_record, dict) else []
        if not isinstance(ipv4, list):
            ipv4 = []
        return host, probe_host(host, [str(x) for x in ipv4], service_cfg)

    print(f"[{name}] probing HTTPS/TLS service for {len(active_hosts)} active host(s)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(work, host) for host in active_hosts]
        for future in concurrent.futures.as_completed(futures):
            host, result = future.result()
            results[host] = result

    transitions: list[str] = []
    for host in active_hosts:
        aggregate, attempts, selected_ips = results[host]
        old, new = apply_service_result(
            service_hosts[host], aggregate, attempts, selected_ips, now, suspect_after, dead_after
        )
        if old != new:
            transitions.append(f"{host}: {old} -> {new}")

    active_set = set(active_hosts)
    alive_hosts = {h for h in active_set if service_hosts.get(h, {}).get("status") == "alive"}
    suspect_hosts = {h for h in active_set if service_hosts.get(h, {}).get("status") == "suspect"}
    dead_hosts = {h for h in active_set if service_hosts.get(h, {}).get("status") == "dead"}
    unknown_hosts = active_set - alive_hosts - suspect_hosts - dead_hosts

    counts_by_result: dict[str, int] = {}
    for host in active_hosts:
        result = str(service_hosts.get(host, {}).get("last_result", "UNKNOWN"))
        counts_by_result[result] = counts_by_result.get(result, 0) + 1

    print(
        f"[{name}] service: ALIVE={counts_by_result.get('ALIVE', 0)} "
        f"FAILURE={counts_by_result.get('FAILURE', 0)} SKIPPED={counts_by_result.get('SKIPPED', 0)} | "
        f"alive={len(alive_hosts)} suspect={len(suspect_hosts)} dead={len(dead_hosts)} unknown={len(unknown_hosts)}"
    )
    for transition in transitions[:30]:
        print(f"[{name}] service transition: {transition}")
    if len(transitions) > 30:
        print(f"[{name}] ... and {len(transitions) - 30} more service transition(s)")

    if not dry_run:
        service_state["version"] = SERVICE_STATE_VERSION
        service_state["updated_at"] = iso(now)
        save_json(service_state_path, service_state)
        write_host_file(alive_path, alive_hosts)
        write_host_file(suspect_path, suspect_hosts)
        write_host_file(dead_path, dead_hosts)
        write_host_file(unknown_path, unknown_hosts)

    return {
        "checked": len(active_hosts),
        "alive": len(alive_hosts),
        "suspect": len(suspect_hosts),
        "dead": len(dead_hosts),
        "unknown": len(unknown_hosts),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Probe HTTPS/TLS health for maintained DNS names")
    parser.add_argument("--config", default="dns_maintenance/config.json")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--collection", action="append")
    parser.add_argument("--dry-run", action="store_true")
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
        config = load_json(config_path, None)
        if not isinstance(config, dict):
            raise ValueError("Config must be a JSON object")
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

        totals = {"checked": 0, "alive": 0, "suspect": 0, "dead": 0, "unknown": 0}
        for collection in collections:
            if not isinstance(collection, dict):
                raise ValueError("Each collection must be an object")
            stats = service_collection(repo_root, collection, args.dry_run)
            for key in totals:
                totals[key] += int(stats.get(key, 0))

        mode = "SERVICE DRY RUN" if args.dry_run else "SERVICE DONE"
        print(
            f"{mode}: checked={totals['checked']}, alive={totals['alive']}, "
            f"suspect={totals['suspect']}, dead={totals['dead']}, unknown={totals['unknown']}"
        )
        return 0
    except (ValueError, KeyError, json.JSONDecodeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
