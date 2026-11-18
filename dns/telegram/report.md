# Telegram DNS Maintenance Report

Generated: `2026-11-18T11:50:51Z`

## DNS lifecycle

| State | Hosts |
|---|---:|
| Active | 34 |
| Pending | 0 |
| Suspect | 1 |
| Quarantine | 0 |
| Excluded | 0 |
| Expired | 10 |

## HTTPS/TLS observation

| State | Hosts |
|---|---:|
| Alive | 31 |
| Unknown | 0 |
| Suspect | 0 |
| Dead | 3 |

## Stability window

The score is based on measured HTTPS/TLS checks within the configured calendar-day window. SKIPPED observations are excluded.

Measured hosts: **34**
Average stability: **91.2%**

## Current HTTPS/TLS failures

| Type | Hosts |
|---|---:|
| TIMEOUT | 2 |
| TLS_CERT_ERROR | 1 |

### Failure details

| Hostname | State | Since | Observations | Last error | IPv4 | Stability | Samples |
|---|---|---|---:|---|---|---:|---:|
| `mail.telegram.org` | dead | `2026-08-20T09:36:06Z` | 307 | TIMEOUT | 95.161.64.16 | 0.0 | 33 |
| `mx101.telegram.org` | dead | `2026-08-20T09:36:06Z` | 307 | TIMEOUT | 95.161.64.16 | 0.0 | 33 |
| `mx110.telegram.org` | dead | `2026-08-20T09:36:06Z` | 307 | TLS_CERT_ERROR | 149.154.162.247 | 0.0 | 33 |

## Discovery

Discovery state updated: `2026-11-18T11:50:51Z`

## Notes

- Public active DNS file: `Telegram_DNS`.
- DNS lifecycle is time-based and does not depend on how many times per day the workflow runs.
- Hostname policy exclusions are semantic decisions and are tracked separately from DNS quarantine.
- HTTPS/TLS health is observational and never removes a hostname from the public DNS file.
