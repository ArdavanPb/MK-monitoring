# Agent Notes — MK-Monitoring

Working rules for every task on this repository. `ARCHITECTURE.md` is the primary
source of truth about the codebase.

## Rules

- Before every task, first read ARCHITECTURE.md and only open files relevant to that task; NEVER re-read the entire project from scratch.
- After every change, add a summary of the change to the Change Log section of this file.

## Change Log

### 2026-09-28 — Interface traffic stats + Network IPs local/external split
- Feature 1 (Interface traffic): new `GET /api/interface-traffic/<id>` (app.py) + `services.get_interface_traffic` (services.py). Returns per-interface live rx/tx rates from `/interface monitor-traffic` (once, all interfaces — via new `routeros_client.safe_api_call_command`, since `safe_api_call` is a print-only helper) plus cumulative totals that prefer the latest `interface_bandwidth_data` sample and fall back to `/interface` rx-byte/tx-byte. Cached 3s (`INTERFACE_TRAFFIC_CACHE_TTL`). `monitor.html` Interfaces table gains Down/Up columns polled every 3s client-side; Down interfaces render "down".
- Feature 2 (local/external split): `services.get_network_ips` classifies each record `group = "local" | "external"` via new `utils.classify_ip` (local = router's own `/ip/address` subnets or RFC1918/loopback/CGNAT/link-local; external = public). Non-host placeholders (0.0.0.0, broadcast, multicast, reserved) are dropped from both groups. `utils.is_internal_ip` extended to cover loopback + CGNAT via an explicit `_INTERNAL_NETWORKS` range tuple. `monitor.html` renders two labeled tables with per-group counts and a shared live filter; row navigation works in both groups.
- 0.0.0.0 decision: excluded from both groups (filtered as a non-host placeholder) rather than a third bucket — cleaner UX, documented in ARCHITECTURE.md.
- Verified: py_compile + pyflakes clean; 155/155 smoke assertions green (17+27+9+7+44+51).

### 2026-09-28 — Final cleanup pass (dead-code sweep + route audit)
- Removed dead endpoints (zero template/JS callers, confirmed by grep across all modules/templates/static):
  - `GET /api/monitor/<id>` — redundant JSON mirror of the monitor page; no bandwidth fields remained.
  - `GET /api/debug/<id>` — raw API-dump debug endpoint, no caller.
  - `GET /api/network-connections/<id>` — superseded by the `/connections` page.
  - `GET /api/alerts/<id>` — redundant JSON accessor; alerts are rendered server-side.
- Removed orphaned/dead code:
  - `services.get_router_connections` (only caller was the removed `/api/network-connections`).
  - `utils._PRIVATE_NETWORKS` (unused; `is_internal_ip` uses `ipaddress.is_private` directly).
  - `render_monitor` `mode` param + `connection_mode` template var (never rendered by `monitor.html`).
  - Unused `{% from "_macros.html" import empty_state %}` in `ip_details.html`.
- Kept `/api/network-ips/<id>` — intentionally API-only JSON accessor (added earlier this session; covered by the smoke suite).
- Confirmed `get_ip_bandwidth_history` + `_HISTORY_PERIODS` are consumed by `GET /api/ip/<id>/<ip>/history` and the details page (period selector).
- Confirmed caching: history endpoint is a direct indexed DB read (no router hit, so no cache needed); connections endpoint uses the 10s cache; header uses the network-IPs 10s cache — no unnecessary router-API bypass.
- Verified: `py_compile` + `pyflakes` clean; 103/103 smoke assertions green (17+26+9+7+44).

### 2026-09-28 — IP details page (per-IP traffic & connections)
- New page `GET /monitor_router/<id>/ip/<ip>` (template `ip_details.html`): header (IP/hostname/MAC/interface/status + Back), Upload/Download/Dropped summary cards with a bits/bytes/packets unit selector, a live two-series "Traffic Rate" chart (Chart.js, polled every 3s, client-side rolling window), and three live tables (Destinations, Services/Ports, Connections).
- New services in `services.py`: `get_ip_traffic_totals` (historical upload/download from `ip_bandwidth_data` deltas), `get_ip_header` (network-IP cache → `ip_bandwidth_data` fallback), `get_ip_connections_details` (live `/ip/firewall/connection` filtered to the IP; destinations/ports/connections; 10s cache; volumes labeled live/estimated). Added `utils.is_valid_ip`.
- New endpoints: `GET /api/ip/<id>/<ip>/history?period=` (wraps `get_ip_bandwidth_history`) and `GET /api/ip/<id>/<ip>/connections`. IP param validated (400), unknown router 404, offline graceful.
- Network IPs rows now navigate to the details page (replaced the placeholder click handler).
- Dropped packets are not collected by the bandwidth collector, so the Dropped card and the "packets" unit show "—" (not fabricated).
- Note: reference images could not be loaded — `assets/reference/*.png` does not exist and the vision backend returned 401; implemented from the written description using the app's own theme.
- Verified: `py_compile` clean; 44/44 new assertions passed; prior network-ips suites (26+9+7) still green.

### 2026-09-28 — /api/network-ips/<id> JSON endpoint
- Added `GET /api/network-ips/<id>` (app.py): returns the same merged, cached `services.get_network_ips()` result as the server-rendered section, JSON-first for the upcoming IP-details page.
- Response: `{"success": true, "data": {"records": [...], "missing_sources": [...], "error": str|None}}`; 404 unknown router, 401 unauthenticated, 200 with degraded data when the router is offline.
- Verified: `py_compile` clean; 9/9 endpoint tests passed (shape, missing_sources, degraded offline, 404, 401).

### 2026-09-28 — Network IPs section (Addresses & Interfaces tab)
- Replaced the "DHCP Leases" section with a "Network IPs" section that merges six RouterOS sources (`/ip/address`, `/ip/arp`, `/ip/neighbor`, `/ip/firewall/connection`, `/ip/dhcp-server/lease`, `/interface`) into one record per IP.
- Added `services.get_network_ips()` (services.py): per-source error handling, dedup by IP, numeric sort, in-process 10s cache, graceful degradation via `missing_sources`. Merged record: `{ip, mac, hostname, interface, sources[], status, status_color}`.
- Template: new card + live filter box + placeholder row click handler in `monitor.html`; `render_monitor`/`monitor_router` in `app.py` now pass `network_ips` + `source_colors`.
- Verified: `py_compile` clean; 33 smoke/unit assertions passed (merge, dedup, sort, statuses, missing-source degradation, no-creds, caching, template render with data and with router disconnected).
- Note: no new HTTP endpoint was added — the section is server-rendered.

### 2026-09-28 — Remove the Bandwidth tab
- Removed the Bandwidth tab (UI + routes + read-side functions); traffic data collection is kept for the upcoming IP-details page.
- Deleted: tab nav button + tab-pane + chart JS in `templates/monitor.html`; Chart.js CDN in `templates/base.html`; routes `api_chart_bandwidth` / `api_chart_interface_bandwidth` in `app.py`; `TIME_PERIODS` + `render_monitor` bandwidth params + `get_ip_bandwidth_stats`/`get_interface_bandwidth_stats` calls in `app.py`; `_PERIODS_MINUTES`, `get_ip_bandwidth_stats`, `get_interface_bandwidth_stats`, `get_interface_bandwidth_data` in `services.py`.
- Kept: `get_ip_bandwidth_history` + `_HISTORY_PERIODS` (per-IP time-series for the next phase), the `ip_bandwidth_data`/`interface_bandwidth_data` tables, `bandwidth_collector.py`, and the collector functions.
- Verified: `py_compile` on all modules; 17/17 smoke tests passed against a temp DB (login, dashboard, all remaining tabs, connections, logs, add-router, change-password; chart endpoints return 404).
