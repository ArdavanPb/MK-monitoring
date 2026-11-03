# MK-Monitoring — Architecture

> Last verified: 2026-11-03 · Status: checked against current code (27 routes, Flow receiver and freshness-aware dashboard)

## 1. Overview

MK-Monitoring is a Flask web application that monitors MikroTik routers. It connects to
each router over three channels — the RouterOS **API** (port 8728), **SNMP** (v2c, port 161), and **Traffic Flow** (NetFlow v5/v9 exports to UDP 2055) —
and renders a dashboard, per-router detail pages (tabs), live firewall connections, system
logs, configuration backups, and alert rules.

Single-file SQLite database (WAL mode) + a few standalone background processes
(SNMP collector, bandwidth collector, Flow collector, alert engine) started by shell scripts. Credentials
are encrypted at rest with Fernet; user passwords use Werkzeug salted password hashes.

## 2. Tech stack & dependencies

| Layer | Technology |
|---|---|
| Language / runtime | Python (Docker pins `python:3.12-slim`; local `venv/` is 3.14) |
| Web framework | Flask 3.1.3 |
| RouterOS API | `routeros-api==0.18` |
| Crypto | `cryptography>=41.0.0` (Fernet) |
| Database | SQLite (stdlib `sqlite3`, WAL mode, `data/routers.db`) |
| SNMP | `snmpget`/`snmpwalk` CLI tools (system `snmp` package — no Python SNMP lib) |
| Frontend | Jinja2 + Bootstrap 5 (CDN) + Bootstrap Icons + axios (CDN) + Chart.js (bundled) |
| Deployment | Docker / Docker Compose (`docker-compose.yml`) |

`requirements.txt` (exact):
```
Flask==3.1.3
routeros-api==0.18
cryptography>=41.0.0
gunicorn==26.2.0
```

## 3. File tree

Legend: ✅ runtime/development file · ❌ local reference/tooling only (excluded from builds).

```
MK-monitoring/
├── app.py                 ✅ Flask app factory + all routes (entrypoint)
├── config.py              ✅ Env-based settings; secret key/fernet key file mgmt
├── db.py                  ✅ Schema + idempotent column migrations + indexes + seeding
├── security.py            ✅ Password hashing, Fernet encrypt/decrypt, CSRF, rate limiter
├── utils.py               ✅ format_bytes, durations, IP classification (is_internal_ip/classify_ip), service names
├── routeros_client.py     ✅ RouterOS API connect + per-router connection pool (safe_api_call/_command) + field normalization + SNMP test
├── services.py            ✅ Business logic: routers, bandwidth, network-IP discovery, connections, logs, backups, alerts
├── snmp_collector.py      ✅ Background SNMP poller (every 60s; started by start.sh/docker-start.sh)
├── bandwidth_collector.py ✅ Background per-IP/interface traffic poller (every 60s)
├── flow_collector.py     ✅ NetFlow v5/v9 UDP parser, source allowlist, deduplicated storage and retention
├── netflow_v9.py         ✅ Stateful RFC 3954 template decoder
├── flow_service.py       ✅ Flow summaries, top IPs/protocols and per-IP totals
├── alert_engine.py        ✅ Background alert rule evaluator (every 30s; email/webhook/syslog)
├── requirements.txt       ✅ Python dependencies
├── Dockerfile             ✅ Container build (installs `snmp`, runs docker-start.sh)
├── docker-compose.yml     ✅ Compose deploy (ports 8080 + UDP 2055, ./data volume, healthcheck)
├── docker-start.sh        ✅ Container entrypoint (Dockerfile CMD)
├── start.sh               ✅ Bare-metal full start: init DB + 4 collectors + backup scheduler + Flask
├── setup.sh               ✅ Creates venv + installs requirements (used by run.sh / README)
├── run.sh                 ✅ Quick start (Flask only)
├── restart-app.sh         ✅ Manual helper: restart Flask (Flask only)
├── .gitignore             ✅ Git ignores (venv, data/, *.db, .env, __pycache__)
├── .dockerignore          ✅ Docker build context ignores
├── README.md              ✅ Main readme and current deployment instructions
├── CONTRIBUTING.md        ✅ Referenced by README ("see CONTRIBUTING.md")
├── data/                  ✅ Runtime dir (routers.db, .secret_key, .fernet_key, backups/) — gitignored
├── venv/                  ✅ Local virtualenv (gitignored) — note: python 3.14, Docker uses 3.12
├── photo/                 ❌ Untracked design mockups (1.png, 2.png) — reference images only
├── doc/                   ❌ Untracked screenshot
├── .crush/                ❌ External tool state (crush.db/logs), not part of the app
├── templates/             ✅ Jinja2 templates (see below)
│   ├── base.html          ✅ Layout + navbar + CSRF meta + CDN JS/CSS + troubleshooting modal
│   ├── login.html         ✅ Login form
│   ├── index.html         ✅ Dashboard (router cards + live connection counts)
│   ├── monitor.html       ✅ Router detail page (tabs: System, Addresses & Interfaces, Alerts, Backups, Logs)
│   ├── ip_details.html    ✅ Per-IP details page (header, traffic summary, live rate chart, destinations/ports/connections)
│   ├── flow.html          ✅ Traffic Flow page (freshness, volume, top IPs/protocols)
│   ├── connections.html   ✅ Live firewall connections (sort/paginate/group/auto-refresh)
│   ├── router_logs.html   ✅ Log viewer (filter/search/pagination/retention/CSV export)
│   ├── add_router.html    ✅ Add/edit router form (API + SNMP + Flow sections)
│   ├── change_password.html ✅ Password change form
│   ├── backup_diff.html   ✅ Backup diff view
│   ├── error.html         ✅ Connection-error page
│   └── _macros.html       ✅ Jinja macros: status_badge, empty_state, stat_card
└── static/
    ├── css/app.css        ✅ App stylesheet (linked from base.html + login.html)
    └── js/app.js          ✅ Shared JS (CSRF attach + flash auto-dismiss)
```

## 4. Main flows

### Login
`GET /login` renders `login.html`. `POST /login` is rate-limited per-IP
(`LOGIN_RATE_LIMIT` attempts / `LOGIN_RATE_WINDOW` sec) then looks up the user in
`users` and verifies via `security.verify_password` (supports legacy SHA-256 hashes,
upgraded to a modern Werkzeug hash on next login). On success sets `session[user_id|username|role]`.
Roles: `admin`(3) > `operator`(2) > `viewer`(1), enforced by `role_required`.
All mutating requests (POST/PUT/DELETE/PATCH) require a CSRF token (`before_request`).

### Connecting to a router (API)
`routeros_client.connect_to_router(host, port, user, pass)` is the raw one-shot
connect: it creates a `RouterOsApiPool(plaintext_login=True, use_ssl=False)` and
returns `(api, connection, error)`. Persistent access goes through
`routeros_client.router_connection(router_id, host, port, user, pass)` — a context
manager that yields `(api, error)` from a per-router connection pool (see
"Connection pooling" below).

Calls always go through `safe_api_call`/`safe_api_call_single`/`safe_api_call_command`
which catch `RouterOsApiConnectionError`/`RouterOsApiError` and return
`{"data","error"}` — never raise. On a connection-level error (socket error /
timeout / fatal communication error) they flag the pooled connection dead so the
pool reconnects it on next use.

### Connection pooling
`routeros_client` keeps one persistent `RouterOsApiPool` per router id in a
module-level registry, guarded by a per-router `threading.Lock` (librouteros
connections are not thread-safe and Flask is threaded, so concurrent requests for
the same router serialize). The app polls every 3s (interface traffic) and 10s
(network IPs), and the network-IPs merge runs six sources — without pooling each
poll opened and closed a connection, so the router logged "user logged in/out via
api" pairs every few seconds. With pooling the router sees ~one login per app
start plus occasional reconnects.

Lifecycle: `router_connection()` reuses the cached connection when it is healthy
(host/port/username match, not marked dead, younger than `ROUTER_API_POOL_MAX_AGE`);
otherwise it closes the old one and reconnects once, surfacing the usual
graceful-degradation error if that reconnect fails. A connection flagged dead by a
failed `safe_api_call*` is reconnected on the next acquire. `close_connection(rid)`
invalidates the pooled connection on router edit/delete; `clear_connection_pool()`
(tests/teardown) closes everything.

One-shot validation connections (add/edit router forms) still use
`connect_to_router` directly and `disconnect()` afterward — they validate fresh
credentials and are not part of the poll loop. The bandwidth collector uses the
pool too, so its once-per-60s sampling reuses one connection across cycles.

The library never sends a RouterOS `quit`: `RouterOsApiPool.disconnect()` just
closes the TCP socket (`connected=False`, `socket.close()`, swap in a
`DummySocket`). MikroTik logs "user <x> logged out" on any API-socket teardown —
quit or bare close alike — so there is no "silent" close. The only way to avoid
periodic logout entries is to not close the connection, which is exactly what the
pool does in steady state.

Observed ~6s login/logout cadence (regression follow-up, 2026-09-29): with the pool
live, the container holds exactly two ESTABLISHED TCP connections to the router —
one from Flask, one from the bandwidth collector (each process has its own
registry) — and they do NOT churn: a 64s `/proc/net/tcp` sample showed the same two
sockets the entire time. The "~6s login/logout" report right after
`docker compose up --build` is the startup burst (both API processes log in, plus a
one-time reconnect — see below) and/or a stale MikroTik memory log. Steady state is
~one login per process at startup plus the `ROUTER_API_POOL_MAX_AGE` recycle (one
pair per router per ~5 min).

Startup artifact: the library classifies "no such command prefix" as fatal and
disconnects the pool, so the collector's first `/ip/accounting` probe closes the
connection and the fallback `/ip/firewall/connection` call fails with "[Errno 9]
Bad file descriptor" until the next 60s cycle reconnects. This self-heals and does
not recur (the collector caches "accounting unavailable" after the first cycle).

### Dashboard (`/`)
`services.list_routers()` → for each router, prefer cached status
(`router_status_cache`) only while it is at most 180s old, else fresh SNMP
metrics if available, else a live API `get_router_info()` (cached via
`set_status_cache`). Flow-only routers show recent export activity when a
packet was received in the last 120s and show Unknown when exports stop;
silence alone does not prove a router is offline. Cards show SNMP/Flow freshness, five-minute Flow average,
CPU/memory/uptime/firmware, and an API live connection count where configured.
Top-level cards show online/offline/unknown routers, SNMP configured, Flow receiving,
and active alerts. Status cache updates replace older rows to avoid unbounded
growth. `snmp_poll_state` tracks SNMP health separately, so API fallback does
not hide a failed SNMP poll. SNMP failures also write an offline cache entry.

### Traffic Flow (NetFlow v5/v9)
`flow_collector.py` listens on `FLOW_LISTEN_HOST:FLOW_PORT` (default
`0.0.0.0:2055/udp`). Every 30s it resolves the source IPv4 for each router
with `flow_enabled=1` (`flow_source_ip`, or `host` if blank). Unknown or
ambiguous sources are ignored. It parses NetFlow v5 headers and 48-byte IPv4
records and v9 template-based IPv4/IPv6 records, rejects malformed/IPFIX packets, deduplicates packets by router,
export time, sequence and engine, then writes `flow_datagrams` and
`flow_records` atomically. Data older than `FLOW_RETENTION_DAYS` (default 7)
is pruned hourly. UDP sender IP is an allowlist, not authentication; network
firewalls should restrict port 2055 to the routers.

`flow_service.py` computes 5-minute/1-hour/24-hour received volume, average rate,
packet/record counts, paginated endpoint totals and protocols. `GET /flow/<id>` renders the
page; `GET /api/flow/<id>?minutes=5|60|1440` refreshes it every 15s. Flow-only
routers can be added without API/SNMP credentials. Per-IP details use the last hour of Flow bytes for summary cards when Flow is
enabled, and API bandwidth estimates otherwise.
`get_network_ips` adds recently observed local Flow IPs to API discovery and
retains them when API is unavailable.
NetFlow v5 is IPv4 only; v9 supports IPv4/IPv6. IPFIX and extrapolation of sampled
traffic are not supported. V9 templates are scoped by router and Source ID, expire
after one hour, and are bounded to 4096 entries. Data with missing templates is
skipped until template refresh; warnings are limited to once per router per minute.
V9 dedup uses engine_type=256 and engine_id=Source ID in the existing packet key. Window summaries use receive time, so a delayed
export appears in the later window.

### Detail page / tabs (`/monitor_router/<id>?tab=`)
SNMP-enabled routers render from stored `snmp_system_metrics`; otherwise a live
`get_detailed_router_info()` (identity, resource, clock, ip/address, interface,
dhcp lease, arp, health, license, log). Tabs: System, Addresses & Interfaces,
Alerts, Backups, Logs. Alerts tab loads rules via `/api/alert_rules/<id>`.

### Network IPs (Addresses & Interfaces tab)
`services.get_network_ips(router)` merges six RouterOS API sources plus recently
observed local Flow IPs into one record per
IP: `/ip/address` (Router), `/ip/arp`, `/ip/neighbor` (MNDP), `/ip/firewall/connection`
(internal IPs only), `/ip/dhcp-server/lease` (hostnames), `/interface` (running state).
Each API source is queried independently; a failing source is recorded in `missing_sources`
and never breaks the section. The merged result is cached in-process for
`NETWORK_IPS_CACHE_TTL` (10s).

Merged record: `{ip, mac, hostname, interface, sources[], status, status_color, group}` —
deduplicated by IP, MAC/interfaces/sources joined (comma-separated), numeric IP sort.
Served two ways: server-rendered into `monitor.html` via the `network_ips` template
context, and as JSON via `GET /api/network-ips/<id>` (same cached, degraded-safe data).

Each record is classified `group = "local" | "external"` via `utils.classify_ip`:
"local" = inside one of the router's own `/ip/address` subnets or an internal range
(RFC1918/loopback/CGNAT/link-local — see `utils.is_internal_ip`); "external" =
global/public unicast. Non-host placeholders (0.0.0.0, broadcast, multicast, reserved)
are dropped from both groups. `monitor.html` renders two labeled tables ("Local
network IPs", "External / remote IPs") with a shared live filter and group counts in
the card title; rows navigate to the IP details page in both groups.

### Interface traffic (Addresses & Interfaces tab)
`services.get_interface_traffic(router_id)` returns, per interface, a live rate
(`rx_rate_bps`/`tx_rate_bps`) and a cumulative total. Totals prefer the latest
`interface_bandwidth_data` sample (written by the bandwidth collector); if absent
they fall back to the `/interface` `rx-byte`/`tx-byte` counters. The result is
cached in-process for `INTERFACE_TRAFFIC_CACHE_TTL` (3s — live rates go stale
fast).

Live rates: RouterOS v7 rejects the bare `/interface monitor-traffic =once=yes`
with "missing =interface=", so the code issues one
`monitor-traffic =interface=<name> =once=yes` per running interface on the pooled
connection and keys each response by interface name. `routeros_client.safe_api_call_command`
wraps the command (the existing `safe_api_call` is a `print` only, which
`monitor-traffic` does not support).

`monitor.html` renders the static Interface table (Name/Type/Status/Down/Up) from
`get_detailed_router_info`, then `GET /api/interface-traffic/<id>` is polled every 3s
(client-side) to fill the Down (rx) / Up (tx) cells with the human-formatted rate and
cumulative total; Down interfaces show "down" instead of a rate.

### IP details page (`/monitor_router/<id>/ip/<ip>`)
Reached by clicking a row in the Network IPs table. Renders `ip_details.html`:
header (IP/hostname/MAC/interface/status from `get_ip_header`), traffic summary
cards (`get_ip_traffic_totals` sums positive deltas in `ip_bandwidth_data`;
Dropped is not collected so it shows "—"), a live rate chart, and three live
tables (Destinations, Services/Ports, Connections) from
`get_ip_connections_details` (filters `/ip/firewall/connection` to the IP).

- `GET /api/ip/<id>/<ip>/history?period=` wraps `get_ip_bandwidth_history`
  (per-IP time-series: download=rx→incoming, upload=tx→outgoing, in Mbps).
  The chart polls it every 3s and keeps a client-side rolling window.
- `GET /api/ip/<id>/<ip>/connections` returns destinations/ports/connections
  (10s cached); volumes are live/estimated, not historical.
- The `<ip>` path parameter is validated with `utils.is_valid_ip` (400 otherwise);
  unknown router → 404; offline router → graceful empty/error state.
- Bundled Chart.js is loaded only on this page (via `ip_details.html` scripts block).
- When Flow is enabled, a separate last-hour Flow summary is shown for the IP.

### Backup
`POST /backup/<id>` → `services.run_router_backup()` calls the `/export` API path,
writes a timestamped `.rsc` under `data/backups/<router_id>/`, prunes beyond
`MAX_BACKUPS` (30). `start.sh`/`docker-start.sh` also schedule a nightly (03:00) backup.
`/backup_diff/<id>` diffs the two newest backups (`diff -u`, fallback difflib).

### Logs
`/router_logs/<id>` pulls `/log` from the router, dedups and stores into
`router_logs` (severity derived from message keywords). Retention per-router
(1/3/7/30/90 days) enforced by `cleanup_old_logs`. CSV export via `/export_logs_csv/<id>`.

### Alerts
`alert_engine.py` evaluates enabled `alert_rules` every 30s (cpu, memory,
interface_down, connections, log_match). On trigger it inserts an `alert_events`
row (status active) and fires the configured action (email via SMTP env vars,
webhook HTTP POST, or syslog). Rules/events are managed via `/api/alert_rules/*` and
`/api/alerts/acknowledge/*`.

## 5. Endpoints / routes

All routes defined in `app.py:_register_routes`. Auth = `login_required` unless noted.

| Method | Path | Auth/role | Input | Output |
|---|---|---|---|---|
| GET/POST | `/login` | public | form: username, password | HTML (redirect to `/` on success) / 429 |
| GET | `/logout` | login | — | redirect `/login` |
| GET/POST | `/change_password` | login | form: current_password, new_password, confirm_password | HTML |
| GET | `/` | login | — | dashboard HTML |
| GET/POST | `/add_router` | operator | form: name, host, port, api_enabled, username, password, snmp_*, flow_enabled, flow_source_ip | HTML |
| GET/POST | `/edit_router/<id>` | operator | same as add_router | HTML |
| POST | `/delete_router/<id>` | admin | — | redirect `/` |
| POST | `/refresh_router/<id>` | operator | — | redirect `/` |
| GET | `/monitor_router/<id>` | login | query: tab | monitor HTML |
| GET | `/api/network-ips/<id>` | login | — | JSON `{success, data:{records, missing_sources, error}}` (API-only JSON accessor) |
| GET | `/api/interface-traffic/<id>` | login | — | JSON `{success, data:{interfaces, error}}` |
| GET | `/monitor_router/<id>/ip/<ip>` | login | path: ip (validated) | IP details HTML |
| GET | `/api/ip/<id>/<ip>/history` | login | query: period (1h/3h/…/1w) | JSON `{success, data:{points, period}}` |
| GET | `/api/ip/<id>/<ip>/connections` | login | — | JSON `{success, data:{destinations, ports, connections, error, estimated}}` |
| GET | `/flow/<id>` | login | — | NetFlow page HTML |
| GET | `/api/flow/<id>` | login | query: minutes=5/60/1440, src/dst, search, view, sort/direction, page/per_page | JSON Flow summary, top IPs/protocols |
| POST | `/backup/<id>` | operator | — | redirect monitor |
| GET | `/backup_diff/<id>` | login | — | HTML diff |
| POST | `/api/alerts/acknowledge/<alert_id>` | operator | — | JSON `{success}` |
| GET/POST | `/api/alert_rules/<id>` | operator | POST: JSON/form rule fields | JSON (list or `{rule_id}`) |
| POST | `/api/alert_rules/<rule_id>/delete` | admin | — | JSON `{success}` |
| POST | `/update_log_retention/<id>` | admin | form: retention_days | redirect logs |
| GET | `/export_logs_csv/<id>` | login | query: severity, search | CSV download |
| GET | `/router_logs/<id>` | login | query: page, severity, search | HTML |
| GET | `/connections/<id>` | login | query: page, sort | HTML |
| GET | `/api/connections/<id>` | login | — | JSON live connections |
| GET | `/api/connection-count/<id>` | login | — | JSON `{count}` |

Static: `/static/*` (Flask built-in). Implicit `HEAD`/`OPTIONS` on every GET.

## 6. Database models / tables

Defined in `db.py:_SCHEMA` (SQLite, WAL, foreign_keys=ON). Column migrations in
`db.py:_COLUMN_MIGRATIONS` run idempotently at startup. The unused legacy SQL
migration script has been removed.

| Table | Key columns | Purpose |
|---|---|---|
| `routers` | name, host, port(8728), username, password(enc), snmp_* (enabled/community/version/port/user/auth/priv), flow_enabled, flow_source_ip | Router definitions + credentials |
| `users` | username (unique), password_hash, role (admin/operator/viewer) | App login accounts |
| `router_status_cache` | router_id, status, last_checked, router_info(JSON), source_type, snmp_port, api_port | Cached online/offline + last info |
| `ip_bandwidth_data` | router_id, ip_address, mac_address, hostname, rx_bytes, tx_bytes, timestamp | Per-IP traffic samples |
| `interface_bandwidth_data` | router_id, interface_name, rx_bytes, tx_bytes, timestamp | Per-interface traffic samples |
| `router_logs` | router_id, timestamp, topics, message, severity, stored_at | Stored router logs |
| `log_retention_settings` | router_id, retention_days | Per-router log retention |
| `snmp_system_metrics` | router_id, cpu_percent, memory_*, uptime, temp, cpu_cores, board_name, architecture, platform, firmware, router_name, source_type | SNMP system metrics |
| `snmp_interface_metrics` | router_id, interface_name, ifindex, rx_bytes, tx_bytes, timestamp | SNMP per-interface counters |
| `snmp_poll_state` | router_id, status, checked_at | Latest SNMP poll health independent of API status |
| `flow_datagrams` | router_id, received_at, export_seconds, sequence, engine_type/id, record_count | NetFlow packet dedup and freshness |
| `flow_records` | router_id, datagram_id, received_at, src/dst IP and port, protocol, bytes, packets, input/output interface | NetFlow IPv4/IPv6 records |
| `alert_rules` | router_id, metric_type, condition, threshold_value, duration_seconds, action, action_config, enabled | Alert rule config |
| `alert_events` | rule_id, router_id, triggered_at, resolved_at, status(active/acknowledged/resolved), message | Alert occurrences |
| `audit_log` | user_id, username, method, path, request_body(redacted), ip_address, created_at | Mutating-request audit trail |

Indexes (`db.py:_INDEXES`): ip_bandwidth (router/time, ip, mac), router_status time,
router_logs (router/time, severity), snmp (system+interface router/time),
alert_events (router/status, rule), audit_log time, Flow (router/time and per-IP lookups).

## 7. How to run

Environment variables (all optional, defaults shown in `config.py`):

| Var | Default | Notes |
|---|---|---|
| `DB_PATH` | `data/routers.db` (or `/app/data/routers.db` in container) | SQLite path |
| `SECRET_KEY` | auto-generated → `data/.secret_key` | Flask session/CSRF signing |
| `FERNET_KEY` | auto-generated → `data/.fernet_key` | Credential encryption key |
| `FLASK_DEBUG` | `false` | |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | |
| `DEFAULT_USERNAME` / `DEFAULT_PASSWORD` | `admin` / random bootstrap file | Seeded only when no users exist |
| `MAX_BACKUPS` | `30` | Backup retention |
| `LOGIN_RATE_LIMIT` / `LOGIN_RATE_WINDOW` | `5` / `60` | Login brute-force limit |
| `CONNECTIONS_CACHE_TTL` / `CONNECTIONS_CACHE_MAX` | `10` / `50` | Firewall-connection cache |
| `ROUTER_API_POOL_MAX_AGE` | `300` | Max age (s) of a pooled RouterOS API connection before recycle |
| `FLOW_LISTEN_HOST` / `FLOW_PORT` | `0.0.0.0` / `2055` | NetFlow v5/v9 UDP listener |
| `FLOW_RETENTION_DAYS` | `7` | Flow history retention |
| `ALERT_SMTP_HOST/PORT/USER/PASS/FROM/TO` | empty | Email alert delivery |

Run:
```bash
# Docker (recommended)
docker-compose up -d            # http://localhost:8080, data persisted in ./data

# Bare metal (full stack)
./setup.sh                      # create venv + install deps
./start.sh                      # init DB + 4 collectors + nightly backup + Flask

# Bare metal (Flask only, no background collectors)
source venv/bin/activate && python app.py
```

Deployment: `Dockerfile` (python:3.12-slim, installs `snmp` + curl, CMD `./docker-start.sh`,
EXPOSE 8080 and 2055/udp) with `docker-compose.yml` (mounts `./data:/app/data`, publishes UDP 2055, healthcheck on
`curl -f localhost:8080`, `restart: unless-stopped`).

## 8. Query, chart and security changes (2026-11-03)

Flow endpoints are aggregated after exact `src`/`dst` filters. Endpoint `search`
is a substring, `view=all|src|dst`, `sort=total|upload|download|ip` and
`direction=asc|desc` are allowlisted. Pages contain 1–200 rows (default 50) and
return `total_ips`, `page`, `pages`, `per_page`; the old 20-IP cap is gone.
`ip` sorting is textual. Summary totals count each record once.

The IP history API chooses Flow for Flow-enabled routers, API counters otherwise.
`flow_service.ip_history` bins exports by UTC receive time into at most about 120
buckets, with null gaps and Mbps averages. Periods include 1m, 5m, 30m and the
existing 1h–1w windows. The frontend no longer truncates a selected window to its
last 60 points. Chart.js 4.4.1 and its MIT license are in `static/vendor/chartjs/`.

New databases use a generated 0600 bootstrap password unless explicitly supplied.
Existing users/roles are never reseeded or elevated. Audit bodies recursively
redact secret keys and action configurations. Sessions use HttpOnly/SameSite=Lax,
optional Secure cookies, and dynamic responses use no-store/nosniff/frame-deny.
`start.sh` fails on database permission errors, without a world-writable fallback.
Docker build inputs are allowlisted; data, keys, backups and tooling are excluded.
`SECURITY.md` documents remaining deployment limitations and publication checks;
`.env.example` contains no real secrets; `.github/workflows/checks.yml` runs tests,
static checks and dependency auditing. Historical duplicate docs were removed.

Docker uses Python 3.12 and Gunicorn 26.2.0 (one worker, four threads, so the
process-local login limiter and router pool remain shared). Shell startup traps
stop web/collector processes on shutdown. Flask 3.1.3 fixes the session cache
header advisory found during dependency auditing.
