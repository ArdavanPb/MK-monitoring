# MK-Monitoring — Architecture

> Last verified: 2026-09-28 · Status: verified against code after the interface-traffic + local/external split (25 routes)

## 1. Overview

MK-Monitoring is a Flask web application that monitors MikroTik routers. It connects to
each router over two channels — the RouterOS **API** (port 8728) and **SNMP** (v2c, port 161) —
and renders a dashboard, per-router detail pages (tabs), live firewall connections, system
logs, configuration backups, and alert rules.

Single-file SQLite database (WAL mode) + a few standalone background processes
(SNMP collector, bandwidth collector, alert engine) started by shell scripts. Credentials
are encrypted at rest with Fernet; user passwords are hashed with PBKDF2.

## 2. Tech stack & dependencies

| Layer | Technology |
|---|---|
| Language / runtime | Python (Docker pins `python:3.9-slim`; local `venv/` is 3.14) |
| Web framework | Flask 2.3.3 |
| RouterOS API | `routeros-api==0.18` |
| Crypto | `cryptography>=41.0.0` (Fernet) |
| Database | SQLite (stdlib `sqlite3`, WAL mode, `data/routers.db`) |
| SNMP | `snmpget`/`snmpwalk` CLI tools (system `snmp` package — no Python SNMP lib) |
| Frontend | Jinja2 + Bootstrap 5 (CDN) + Bootstrap Icons + axios + Chart.js (CDN) |
| Deployment | Docker / Docker Compose (`docker-compose.yml`) |

`requirements.txt` (exact):
```
Flask==2.3.3
routeros-api==0.18
cryptography>=41.0.0
```

## 3. File tree

Legend: ✅ used · ❌ possibly unused (not imported/referenced anywhere).

```
MK-monitoring/
├── app.py                 ✅ Flask app factory + all routes (entrypoint)
├── config.py              ✅ Env-based settings; secret key/fernet key file mgmt
├── db.py                  ✅ Schema + idempotent column migrations + indexes + seeding
├── security.py            ✅ Password hashing, Fernet encrypt/decrypt, CSRF, rate limiter
├── utils.py               ✅ format_bytes, durations, IP classification (is_internal_ip/classify_ip), service names
├── routeros_client.py     ✅ RouterOS API connect/call (safe_api_call + safe_api_call_command) + field normalization + SNMP test
├── services.py            ✅ Business logic: routers, bandwidth, network-IP discovery, connections, logs, backups, alerts
├── snmp_collector.py      ✅ Background SNMP poller (every 60s; started by start.sh/docker-start.sh)
├── bandwidth_collector.py ✅ Background per-IP/interface traffic poller (every 60s)
├── alert_engine.py        ✅ Background alert rule evaluator (every 30s; email/webhook/syslog)
├── requirements.txt       ✅ Python dependencies
├── Dockerfile             ✅ Container build (installs `snmp`, runs docker-start.sh)
├── docker-compose.yml     ✅ Compose deploy (port 8080, ./data volume, healthcheck)
├── docker-start.sh        ✅ Container entrypoint (Dockerfile CMD)
├── start.sh               ✅ Bare-metal full start: init DB + 3 collectors + backup scheduler + Flask
├── setup.sh               ✅ Creates venv + installs requirements (used by run.sh / README)
├── run.sh                 ✅ Quick start (Flask only)
├── restart-app.sh         ✅ Manual helper: restart Flask (documented in PROJECT_DOCUMENT.md)
├── .gitignore             ✅ Git ignores (venv, data/, *.db, .env, __pycache__)
├── .dockerignore          ✅ Docker build context ignores
├── migration.sql          ❌ Legacy one-shot SQL; superseded by db.py `_COLUMN_MIGRATIONS`. Not referenced.
├── README.md              ✅ Main readme (references ./quickstart.sh which does NOT exist — stale)
├── CONTRIBUTING.md        ✅ Referenced by README ("see CONTRIBUTING.md")
├── PROJECT_DOCUMENT.md    ❌ Older duplicate architecture doc — superseded by this file
├── CRUSH.md               ❌ Historical "stability rules" note (deleted in commit a698a70, re-added)
├── BANDWIDTH_CHART_FEATURE.md   ❌ Historical feature note, unreferenced
├── CHART_FIX_SUMMARY.md         ❌ Historical note, unreferenced
├── CHART_TROUBLESHOOTING.md     ❌ Historical note, unreferenced
├── CONNECTIONS_FEATURE.md       ❌ Historical note, unreferenced
├── FIREWALL_CONNECTIONS_FEATURE.md ❌ Historical note, unreferenced
├── ROUTER_INFO_IMPROVEMENTS.md  ❌ Historical note, unreferenced
├── data/                  ✅ Runtime dir (routers.db, .secret_key, .fernet_key, backups/) — gitignored
├── venv/                  ✅ Local virtualenv (gitignored) — note: python 3.14, Docker uses 3.9
├── photo/                 ❌ Untracked design mockups (1.png, 2.png) — reference images only
├── doc/                   ❌ Untracked screenshot
├── .crush/                ❌ External tool state (crush.db/logs), not part of the app
├── templates/             ✅ Jinja2 templates (see below)
│   ├── base.html          ✅ Layout + navbar + CSRF meta + CDN JS/CSS + troubleshooting modal
│   ├── login.html         ✅ Login form
│   ├── index.html         ✅ Dashboard (router cards + live connection counts)
│   ├── monitor.html       ✅ Router detail page (tabs: System, Addresses & Interfaces, Alerts, Backups, Logs)
│   ├── ip_details.html    ✅ Per-IP details page (header, traffic summary, live rate chart, destinations/ports/connections)
│   ├── connections.html   ✅ Live firewall connections (sort/paginate/group/auto-refresh)
│   ├── router_logs.html   ✅ Log viewer (filter/search/pagination/retention/CSV export)
│   ├── add_router.html    ✅ Add/edit router form (API + SNMP sections)
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
upgraded to PBKDF2 on next login). On success sets `session[user_id|username|role]`.
Roles: `admin`(3) > `operator`(2) > `viewer`(1), enforced by `role_required`.
All mutating requests (POST/PUT/DELETE/PATCH) require a CSRF token (`before_request`).

### Connecting to a router (API)
`routeros_client.connect_to_router(host, port, user, pass)` creates a
`RouterOsApiPool(plaintext_login=True, use_ssl=False)`, returns `(api, connection, error)`.
Calls always go through `safe_api_call`/`safe_api_call_single` which catch
`RouterOsApiConnectionError`/`RouterOsApiError` and return `{"data","error"}` — never raise.
Callers must call `connection.disconnect()` (usually in a `finally`).

### Dashboard (`/`)
`services.list_routers()` → for each router, prefer cached status
(`router_status_cache`), else SNMP detailed info if `snmp_enabled`, else a live API
`get_router_info()` (cached via `set_status_cache`). Renders router cards with
online/offline badge, CPU/memory/uptime/firmware, and a live connection count
(`/api/connection-count/<id>` polled every 30s).

### Detail page / tabs (`/monitor_router/<id>?tab=`)
SNMP-enabled routers render from stored `snmp_system_metrics`; otherwise a live
`get_detailed_router_info()` (identity, resource, clock, ip/address, interface,
dhcp lease, arp, health, license, log). Tabs: System, Addresses & Interfaces,
Alerts, Backups, Logs. Alerts tab loads rules via `/api/alert_rules/<id>`.

### Network IPs (Addresses & Interfaces tab)
`services.get_network_ips(router)` merges six RouterOS sources into one record per
IP: `/ip/address` (Router), `/ip/arp`, `/ip/neighbor` (MNDP), `/ip/firewall/connection`
(internal IPs only), `/ip/dhcp-server/lease` (hostnames), `/interface` (running state).
Each source is queried independently; a failing source is recorded in `missing_sources`
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
(`rx_rate_bps`/`tx_rate_bps` from `/interface monitor-traffic`, once, all interfaces)
and a cumulative total. Totals prefer the latest `interface_bandwidth_data` sample
(written by the bandwidth collector); if absent they fall back to the `/interface`
`rx-byte`/`tx-byte` counters. The result is cached in-process for
`INTERFACE_TRAFFIC_CACHE_TTL` (3s — live rates go stale fast).

`monitor.html` renders the static Interface table (Name/Type/Status/Down/Up) from
`get_detailed_router_info`, then `GET /api/interface-traffic/<id>` is polled every 3s
(client-side) to fill the Down (rx) / Up (tx) cells with the human-formatted rate and
cumulative total; Down interfaces show "down" instead of a rate. `routeros_client.safe_api_call_command`
wraps the RouterOS `monitor-traffic` command (the existing `safe_api_call` is a
`print` only, which `monitor-traffic` does not support).

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
- Chart.js CDN is loaded only on this page (via `ip_details.html` scripts block).

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
| GET/POST | `/add_router` | operator | form: name, host, port, api_enabled, username, password, snmp_* | HTML |
| GET/POST | `/edit_router/<id>` | operator | same as add_router | HTML |
| POST | `/delete_router/<id>` | admin | — | redirect `/` |
| POST | `/refresh_router/<id>` | operator | — | redirect `/` |
| GET | `/monitor_router/<id>` | login | query: tab | monitor HTML |
| GET | `/api/network-ips/<id>` | login | — | JSON `{success, data:{records, missing_sources, error}}` (API-only JSON accessor) |
| GET | `/api/interface-traffic/<id>` | login | — | JSON `{success, data:{interfaces, error}}` |
| GET | `/monitor_router/<id>/ip/<ip>` | login | path: ip (validated) | IP details HTML |
| GET | `/api/ip/<id>/<ip>/history` | login | query: period (1h/3h/…/1w) | JSON `{success, data:{points, period}}` |
| GET | `/api/ip/<id>/<ip>/connections` | login | — | JSON `{success, data:{destinations, ports, connections, error, estimated}}` |
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
`db.py:_COLUMN_MIGRATIONS` run idempotently at startup — `migration.sql` is a legacy
duplicate of some of these and is not run by anything.

| Table | Key columns | Purpose |
|---|---|---|
| `routers` | name, host, port(8728), username, password(enc), snmp_* (enabled/community/version/port/user/auth/priv) | Router definitions + credentials |
| `users` | username (unique), password_hash, role (admin/operator/viewer) | App login accounts |
| `router_status_cache` | router_id, status, last_checked, router_info(JSON), source_type, snmp_port, api_port | Cached online/offline + last info |
| `ip_bandwidth_data` | router_id, ip_address, mac_address, hostname, rx_bytes, tx_bytes, timestamp | Per-IP traffic samples |
| `interface_bandwidth_data` | router_id, interface_name, rx_bytes, tx_bytes, timestamp | Per-interface traffic samples |
| `router_logs` | router_id, timestamp, topics, message, severity, stored_at | Stored router logs |
| `log_retention_settings` | router_id, retention_days | Per-router log retention |
| `snmp_system_metrics` | router_id, cpu_percent, memory_*, uptime, temp, cpu_cores, board_name, architecture, platform, firmware, router_name, source_type | SNMP system metrics |
| `snmp_interface_metrics` | router_id, interface_name, ifindex, rx_bytes, tx_bytes, timestamp | SNMP per-interface counters |
| `alert_rules` | router_id, metric_type, condition, threshold_value, duration_seconds, action, action_config, enabled | Alert rule config |
| `alert_events` | rule_id, router_id, triggered_at, resolved_at, status(active/acknowledged/resolved), message | Alert occurrences |
| `audit_log` | user_id, username, method, path, request_body(redacted), ip_address, created_at | Mutating-request audit trail |

Indexes (`db.py:_INDEXES`): ip_bandwidth (router/time, ip, mac), router_status time,
router_logs (router/time, severity), snmp (system+interface router/time),
alert_events (router/status, rule), audit_log time.

## 7. How to run

Environment variables (all optional, defaults shown in `config.py`):

| Var | Default | Notes |
|---|---|---|
| `DB_PATH` | `data/routers.db` (or `/app/data/routers.db` in container) | SQLite path |
| `SECRET_KEY` | auto-generated → `data/.secret_key` | Flask session/CSRF signing |
| `FERNET_KEY` | auto-generated → `data/.fernet_key` | Credential encryption key |
| `FLASK_DEBUG` | `false` | |
| `HOST` / `PORT` | `0.0.0.0` / `8080` | |
| `DEFAULT_USERNAME` / `DEFAULT_PASSWORD` | `admin` / `admin` | Seeded admin account |
| `MAX_BACKUPS` | `30` | Backup retention |
| `LOGIN_RATE_LIMIT` / `LOGIN_RATE_WINDOW` | `5` / `60` | Login brute-force limit |
| `CONNECTIONS_CACHE_TTL` / `CONNECTIONS_CACHE_MAX` | `10` / `50` | Firewall-connection cache |
| `ALERT_SMTP_HOST/PORT/USER/PASS/FROM/TO` | empty | Email alert delivery |

Run:
```bash
# Docker (recommended)
docker-compose up -d            # http://localhost:8080, data persisted in ./data

# Bare metal (full stack)
./setup.sh                      # create venv + install deps
./start.sh                      # init DB + 3 collectors + nightly backup + Flask

# Bare metal (Flask only, no background collectors)
source venv/bin/activate && python app.py
```

Deployment: `Dockerfile` (python:3.9-slim, installs `snmp` + curl, CMD `./docker-start.sh`,
EXPOSE 8080) with `docker-compose.yml` (mounts `./data:/app/data`, healthcheck on
`curl -f localhost:8080`, `restart: unless-stopped`).

## 8. Known discrepancies / findings (for later phases)

1. `README.md` references `./quickstart.sh` — that script does not exist. (stale doc)
2. `migration.sql` is superseded by `db.py` programmatic migrations and never executed. (dead)
3. `PROJECT_DOCUMENT.md` is stale — it lists removed endpoints (`/api/monitor`,
   `/api/debug`, `/api/network-connections`, `/api/alerts`) and the old bandwidth
   tab. Dead code was removed in the final cleanup pass.
4. `venv/` is Python 3.14; Dockerfile pins 3.9. Unverified whether the venv actually runs the app.
5. `PROJECT_DOCUMENT.md`, `CRUSH.md`, and the 6 `*_FEATURE.md`/`*_SUMMARY.md`/`*_TROUBLESHOOTING.md`
   files are historical/duplicate docs, unreferenced.
