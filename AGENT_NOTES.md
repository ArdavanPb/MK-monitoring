# Agent Notes — MK-Monitoring

Working rules for every task on this repository. `ARCHITECTURE.md` is the primary
source of truth about the codebase.

## Rules

- Before every task, first read ARCHITECTURE.md and only open files relevant to that task; NEVER re-read the entire project from scratch.
- After every change, check the affected documentation and project structure, update README.md/ARCHITECTURE.md when behavior or files change, and add a summary to the Change Log section of this file.

## Change Log

### 2026-11-03 — Flow exploration, IP charts and publication cleanup
- Replaced the 20-IP cap with counted pagination, source/destination filters, endpoint search/view and upload/download/total sorting.
- Connected per-IP charts to Flow exports; added 1m/5m/30m windows, bounded receive-time buckets and null gaps; removed the last-60-points truncation and bundled Chart.js with its license.
- Removed fixed bootstrap credentials, recursive audit secret leakage and the unsafe shared /tmp DB fallback. Added session/response safeguards and a strict Docker build-context allowlist.
- Removed unused historical documentation and migration.sql (copies preserved locally in /tmp/mk-monitoring-retired-docs). Added SECURITY.md, .env.example and CI; updated current architecture and setup instructions.
- Updated Flask to 3.1.3 after the dependency audit flagged its session cache-header advisory; Docker now uses Python 3.12 and Gunicorn 26.2.0.
- Validation: 21 tests passed both locally and in the final Python 3.12 image; browser checks confirmed source/destination filters and 1m/5m/30m chart rendering without console errors. The patched dependency audit reports no known vulnerabilities. Git-history token/private-key pattern scan found no matches (not a comprehensive secret audit).
- Deployment verified: container healthy, TCP 8080 and UDP 2055 published, host login HTTP 200; live one-hour query returned 1810 IPs (50/page) in 94 ms, fresh Flow data, and all three short chart APIs returned populated Flow points. New image contains no local data, key files, .env, Git or tests; bundled chart is present. Existing passwords remain unchanged; the operator was told to replace a legacy default password.


### 2026-11-03 — NetFlow v9 support
- Added RFC 3954 template decoding for IPv4/IPv6, exporter/Source-ID isolation, expiry and bounded caches, options handling and throttled warnings. V5 remains supported.
- Updated setup examples to version=9 and documented template refresh behavior.
- Validation: 15 tests cover v5/v9 parsing, template isolation/expiry, options, IPv6, SQLite storage and UDP receipt. Rebuilt and recreated the Docker service; published ports remained attached.
- Live verification: router 3 exported v9 templates/data; 225 flow records (351050 bytes) were stored by 07:04:22 UTC, summary fresh=true with 20 top IPs, and `/api/flow/3?minutes=5` returned HTTP 200. API port 8728 remains refused independently.


### 2026-11-03 — Docker browser port recovery
- Diagnosed a healthy container whose `docker compose ps` showed no published ports although Compose configured TCP 8080 and UDP 2055. `docker inspect` showed `NetworkSettings.Networks={}` and the Compose network had no attached container.
- Connected the running container to `mk-monitoring_mikrotik-monitor-network`. Verified Docker now publishes both ports and HTTP on `127.0.0.1:8080` and the host LAN address on port 8080 redirects to `/login`.
- The router API at the router management address on port 8728 then returned `Connection refused` from both host and container; this is separate from browser access. Added the conditional recovery steps to README.

### 2026-11-03 — Traffic Flow receiver and freshness-aware monitoring
- Added a NetFlow v5 UDP receiver, source-IP allowlist, strict packet validation, deduplication, SQLite flow tables/indexes, seven-day retention, and 5-minute/1-hour summary queries.
- Added Flow configuration to router add/edit, a live Flow page, per-IP Flow totals, and dashboard cards for Flow freshness, SNMP freshness, average Flow rate and active alerts. Flow-only routers are supported.
- Corrected stale SNMP/API status handling and status-cache growth; SNMP polling now marks failures offline and prefers 64-bit interface counters. Removed SNMP community logging from connection tests.
- Wired UDP 2055 into Docker and both full-stack startup scripts. Updated README, ARCHITECTURE, CONTRIBUTING, and marked PROJECT_DOCUMENT historical.
- Verified with `venv/bin/python -m unittest discover -s tests -v` (7 tests, including a real localhost UDP export), Python compilation, and `git diff --check`. Live-router and container verification still require deployment.

### 2026-09-29 — Verified: pool is reusing; ~6s churn is startup + stale log; fixed monitor-traffic
- Environment verified in the running container (not just host copy): `services.py` has `router_connection` at all 6 API call sites and zero `connect_to_router`/`disconnect`; `routeros_client.py` has the pool. No volume shadows the code (`docker-compose.yml` mounts only `./data:/app/data`).
- Double-instance check: one container with four processes (Flask `app.py`, `bandwidth_collector.py`, `alert_engine.py`, `snmp_collector.py`); only Flask and the bandwidth collector hit the RouterOS API. No host cron/systemd/second checkout/rogue API client. The host LAN address matches the log source IP.
- Steady state is churn-free: `docker exec … cat /proc/net/tcp` sampled over 64s shows exactly two ESTABLISHED connections to the router management address on port 8728 (one per API process) with unchanged sockets/inodes the entire time. No `connection error` log lines after the startup burst.
- The "~6s login/logout" after `docker compose up --build` is the startup burst (Flask + collector login, plus a one-time `/ip/accounting` "no such command prefix" fatal error → library `disconnect()` → fallback `/ip/firewall/connection` "[Errno 9] Bad file descriptor" → next-cycle reconnect) and/or a stale MikroTik memory log. It does not recur.
- Fixed a real, separate bug: `get_interface_traffic` used the bare `/interface monitor-traffic =once=yes`, which this router (v7) rejects with "missing =interface=" — live rates were always 0. Now issues one `monitor-traffic =interface=<name> =once=yes` per running interface on the pooled connection. Updated `smoke_interface_traffic.py`'s fake to return per-interface data.
- Verified: full smoke suite green — 17+51+44+9+7+27+12 = 167 assertions (includes pool reuse, reconnect, thread-safety, zero-disconnect, and per-interface monitor checks).

### 2026-09-29 — Diagnosis: MikroTik still shows ~6s login/logout pairs
- Finding 1 (library): `routeros-api==0.18` never sends a RouterOS `quit`. `RouterOsApiPool.disconnect()` only closes the TCP socket (`connected=False`; `socket.close()`; swap in `DummySocket`); `base_api.Connection` has no quit/close command. MikroTik logs "logged out" on any API-socket teardown, so a bare close and a quit are indistinguishable — there is no silent-close option. Conclusion: the only way to avoid periodic "logged out" is to keep the connection open (which the pool does).
- Finding 2 (~6s cadence): interface-traffic is polled every 3s (`monitor.html` setInterval 3000) but `INTERFACE_TRAFFIC_CACHE_TTL` is also 3s, so every other poll is a cache hit and the router is queried only every ~6s. The pre-pool code did connect+disconnect per query → one login/logout pair every ~6s. Not two 3s pollers (the IP-details 3s `pollHistory` is a DB read; its `pollConnections` is 10s).
- Finding 3 (MAX_AGE): `ROUTER_API_POOL_MAX_AGE=300` is correct (`time.monotonic()` both sides); it recycles each pooled connection once per ~5 min (one pair per router per 5 min), not per 6s — not the cause.
- Action: no code bug in the pool — steady state never calls `disconnect()` (only the dead/stale recycle, `close_connection` on edit/delete, and teardown do). Added assertion to `smoke_connection_pool.py`: zero disconnects across 5 sequential poll cycles. The ~6s pairs are explained by the app still running pre-pool code; restart Flask (`./restart-app.sh` or `docker-compose restart`) to load the pool.
- Verified: smoke_connection_pool 12/12; existing suites 17+51+44+9+7+27 = 155/155.

### 2026-09-29 — Per-router API connection pooling (fix login churn)
- Root cause: every API poll opened and closed a fresh RouterOS connection, so the 3s interface-traffic poll + 10s network-IPs poll (6-source merge) produced "user test logged in/out via api" log pairs on the router every few seconds (CPU/RAM cost + a flooded memory log).
- Fix in `routeros_client.py`: a per-router persistent connection pool. One `RouterOsApiPool` per router id in a module-level registry, guarded by a per-router `threading.Lock` (librouteros connections are not thread-safe; Flask is threaded). New public surface:
  - `router_connection(router_id, host, port, user, pass)` — context manager yielding `(api, error)`; reuses a healthy cached connection, else reconnects once and surfaces the usual graceful-degradation error on failure.
  - `close_connection(router_id)` (router edit/delete), `clear_connection_pool()` (tests/teardown), `mark_connection_dead(api)` (called by `safe_api_call*`).
  - `MAX_CONNECTION_AGE` → `config.ROUTER_API_POOL_MAX_AGE` (default 300s) recycles idle connections to avoid zombie sockets behind NAT/idle timeouts.
- Health handling: `safe_api_call`/`safe_api_call_command` mark the pooled connection dead on `RouterOsApiConnectionError`, fatal/communication errors, and socket timeouts/resets; a plain `RouterOsApiError` (e.g. "no such command") does NOT. The pool reconnects the dead connection on the next acquire (one reconnect attempt; failure flows into existing graceful-degradation paths).
- Callers converted to `router_connection` (kept `safe_api_call*` signatures unchanged): `app.py` index/monitor_router/router_logs; `services.py` update_router_status_cache/get_network_ips/get_interface_traffic/get_ip_connections_details/get_live_firewall_connections (body extracted to `_fetch_firewall_connections`)/run_router_backup; `bandwidth_collector.py` (one connection across 60s cycles). `add_router`/`edit_router` still use one-shot `connect_to_router` (fresh-credential validation); `edit_router`/`delete_router` call `close_connection(router_id)`.
- Polling intervals unchanged (3s/10s) — pooling is the fix, not slower polls.
- Verified: `py_compile` + `pyflakes` clean; new `smoke_connection_pool.py` 11/11 (one connect across sequential network-IPs + interface-traffic calls, exactly one reconnect after a failed call, thread-safety smoke with max-active==1); existing suites still green 17+51+44+9+7+27 = 155/155. Existing scratch tests updated to call `clear_connection_pool()` where they switch `connect_to_router` to a disconnected fake (pool would otherwise cache the earlier connection).
- Deploy note: after deploying, the MikroTik log should show ~one login per app start + occasional reconnects, not per-second pairs.

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

### 2026-11-03 — Traffic comparison
- Added explicit Flow/API history selection and selected-window Flow byte totals.
- Fixed missing API baseline handling; counter decreases and long gaps are unknown rather than fabricated zero rates.
- Screenshot discrepancy remains unconfirmed pending router export/FastTrack settings and aligned measurement windows. Added API baseline/reset/direction regression coverage.

### 2026-11-03 — SNMP display wiring
- Fixed missing Network IP context on both SNMP render branches.
- Routed SNMP interface rates to stored counter deltas instead of requiring API credentials; missing/stale/reset samples stay unknown.
- Removed fabricated Up statuses and clarified that router address inventory is not collected via SNMP yet.
- Added regression coverage for interface rates without API credentials.

### 2026-11-03 — Combined-source monitoring
- Added fresh SNMP IPv4 inventory/operational state with numeric full table indices.
- Integrated inventory and Flow discovery on SNMP pages; retained useful views on API failure and API enrichment when available.
- Added explicit historical Flow-peer fallback for unavailable live API connections, without combining traffic sources.
- Added source integration, SNMP table-index and interface-rate regressions.

- Live validation: 6 SNMP IPv4 addresses, 35 inventory interfaces and 68 merged network IPs returned. Rates are derived from SNMP counters; obsolete names are excluded when current inventory is available. Full suite: 31 tests passed.
