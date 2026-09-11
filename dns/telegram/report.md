# Telegram DNS Maintenance Report

Generated: `2026-09-11T17:46:17Z`

## DNS lifecycle

| State | Hosts |
|---|---:|
| Active | 19 |
| Pending | 1 |
| Suspect | 0 |
| Quarantine | 7 |
| Expired | 0 |

## HTTPS/TLS observation

| State | Hosts |
|---|---:|
| Alive | 15 |
| Unknown | 1 |
| Suspect | 0 |
| Dead | 3 |

## Stability window

The score is based on measured HTTPS/TLS checks within the configured calendar-day window. SKIPPED observations are excluded.

Measured hosts: **19**
Average stability: **78.9%**

## Current HTTPS/TLS failures

| Type | Hosts |
|---|---:|
| TIMEOUT | 2 |
| TLS_CERT_ERROR | 2 |

### Failure details

| Hostname | State | Since | Observations | Last error | IPv4 | Stability | Samples |
|---|---|---|---:|---|---|---:|---:|
| `mail.telegram.org` | dead | `2026-08-20T09:36:06Z` | 87 | TIMEOUT | 95.161.64.16 | 0.0 | 53 |
| `mx101.telegram.org` | dead | `2026-08-20T09:36:06Z` | 87 | TIMEOUT | 95.161.64.16 | 0.0 | 53 |
| `mx110.telegram.org` | dead | `2026-08-20T09:36:06Z` | 87 | TLS_CERT_ERROR | 149.154.162.247 | 0.0 | 53 |
| `tonbridge.telegram.org` | unknown | `2026-09-11T17:46:17Z` | 1 | TLS_CERT_ERROR | 149.154.161.151 | 0.0 | 1 |

## Discovery

Discovery state updated: `2026-09-11T17:46:17Z`

## Notes

- Public active DNS file: `Telegram_DNS`.
- DNS lifecycle is time-based and does not depend on how many times per day the workflow runs.
- HTTPS/TLS health is observational and never removes a hostname from the public DNS file.
