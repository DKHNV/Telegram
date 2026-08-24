# Telegram DNS Maintenance Report

Generated: `2026-08-24T15:03:29Z`

## DNS lifecycle

| State | Hosts |
|---|---:|
| Active | 18 |
| Pending | 0 |
| Suspect | 7 |
| Quarantine | 0 |
| Expired | 0 |

## HTTPS/TLS observation

| State | Hosts |
|---|---:|
| Alive | 15 |
| Unknown | 0 |
| Suspect | 3 |
| Dead | 0 |

## Stability window

The score is based on measured HTTPS/TLS checks within the configured calendar-day window. SKIPPED observations are excluded.

Measured hosts: **18**
Average stability: **83.3%**

## Current HTTPS/TLS failures

| Type | Hosts |
|---|---:|
| TIMEOUT | 2 |
| TLS_CERT_ERROR | 1 |

### Failure details

| Hostname | State | Since | Observations | Last error | IPv4 | Stability | Samples |
|---|---|---|---:|---|---|---:|---:|
| `mail.telegram.org` | suspect | `2026-08-20T09:36:06Z` | 22 | TIMEOUT | 95.161.64.16 | 0.0 | 24 |
| `mx101.telegram.org` | suspect | `2026-08-20T09:36:06Z` | 22 | TIMEOUT | 95.161.64.16 | 0.0 | 24 |
| `mx110.telegram.org` | suspect | `2026-08-20T09:36:06Z` | 22 | TLS_CERT_ERROR | 149.154.162.247 | 0.0 | 24 |

## Discovery

Discovery state updated: `2026-08-24T15:03:29Z`

## Notes

- Public active DNS file: `Telegram_DNS`.
- DNS lifecycle is time-based and does not depend on how many times per day the workflow runs.
- HTTPS/TLS health is observational and never removes a hostname from the public DNS file.
