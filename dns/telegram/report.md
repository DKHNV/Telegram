# Telegram DNS Maintenance Report

> Generated automatically at `2026-08-20T08:01:57Z`. HTTPS/TLS health is observational and does **not** remove entries from the public DNS list.

## Overview

| Layer | Metric | Count |
|---|---|---:|
| DNS | Active | 18 |
| DNS | Pending | 0 |
| DNS | Suspect | 7 |
| DNS | Quarantine | 0 |
| DNS | Expired | 0 |
| HTTPS/TLS | Alive | 15 |
| HTTPS/TLS | Unknown | 0 |
| HTTPS/TLS | Suspect | 3 |
| HTTPS/TLS | Dead | 0 |

## Latest HTTPS/TLS check

State updated: `2026-08-20T08:01:53Z`

| Result | Count |
|---|---:|
| ALIVE | 15 |
| FAILURE | 3 |
| SKIPPED | 0 |
| UNTESTED/other | 0 |

## Stability window

`stability_score` is the percentage of successful HTTPS/TLS checks among the last measured checks. `SKIPPED` checks are excluded. The history window is capped by `service_check.history_limit`.

| Score | Hosts |
|---|---:|
| 100% | 15 |
| 80-99.9% | 0 |
| <80% | 3 |
| n/a | 0 |

## Current failures

| Type | Hosts |
|---|---:|
| TIMEOUT | 2 |
| TLS_CERT_ERROR | 1 |

### Failure details

| Hostname | State | Consecutive failures | Last error | IPv4 | Stability | Samples | Last check |
|---|---|---:|---|---|---:|---:|---|
| `mail.telegram.org` | suspect | 3 | TIMEOUT | 95.161.64.16 | 0.0% | 1 | `2026-08-20T08:01:53Z` |
| `mx101.telegram.org` | suspect | 3 | TIMEOUT | 95.161.64.16 | 0.0% | 1 | `2026-08-20T08:01:53Z` |
| `mx110.telegram.org` | suspect | 3 | TLS_CERT_ERROR | 149.154.162.247 | 0.0% | 1 | `2026-08-20T08:01:53Z` |

## Discovery

Discovery state updated: `2026-08-20T08:01:53Z`  
DNS state updated: `2026-08-20T08:01:53Z`

New CT-discovered hosts imported in the latest DNS-maintenance run: **0**.

### Certificate Transparency cursors

| Root domain | Caught up | Last poll |
|---|---|---|
| `t.me` | yes | `2026-08-20T08:01:53Z` |
| `telegram.me` | yes | `2026-08-20T08:01:53Z` |
| `telegram.org` | yes | `2026-08-20T08:01:53Z` |

## Notes

- Public active DNS file: `Telegram_DNS` (18 hostnames).
- HTTPS/TLS health is a separate signal. A host may be a valid DNS/service endpoint even when TCP/443 or ordinary HTTPS is not applicable.
- DNS lifecycle rules remain unchanged by this report.
