# MK-Monitoring — MikroTik Router Monitoring Application

## Overview

A Flask-based web application that connects to MikroTik routers via the RouterOS API (`routeros-api` Python library) to monitor and display real-time router information, network traffic, firewall connections, and system logs.

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Python 3.9+ / Flask 2.3.3 |
| **Database** | SQLite (single file: `data/routers.db`) |
| **Router Connectivity** | `routeros-api==0.18` (MikroTik RouterOS API) |
| **Scheduler** | `schedule==1.2.1` (background data collection) |
| **Frontend** | Bootstrap 5 / Jinja2 Templates |
| **Deployment** | Docker / Docker Compose |
| **Port** | 8080 |

## Core Features

### 1. Router Management
- Add/delete MikroTik routers with IP, port (default 8728), username, password
- Test connection before saving
- Dashboard with status badges (online/offline)
- Auto-refresh every 60 seconds

### 2. Router Monitoring (`/monitor_router/<id>`)
- **System Identity**: Router name, firmware, architecture, board, platform
- **Resource Usage**: Memory (total/free/used with % progress bar), CPU load, uptime
- **Network Addresses**: All configured IP addresses on the router
- **DHCP Leases**: Connected clients with IP, MAC, hostname, status
- **ARP Table**: MAC address resolution
- **System Health**: Temperature, voltage, etc. (if supported by hardware)
- **License Info**: Software ID, level
- **Bandwidth Charts**: Per-IP bandwidth with selectable time periods (1m/5m/15m/30m/1h/3h/6h/12h/24h/3d/1w)
- **Interface Bandwidth**: Per-interface bandwidth charting

### 3. Live Firewall Connections (`/connections/<id>`)
Sophos/FortiGate-style real-time connection monitoring:
- Lists active outbound internet connections from internal IPs to external destinations
- Shows: source IP, hostname, destination IP, service (port-based), upload/download bytes, duration, protocol
- Sorting by download/upload/duration/source IP
- Pagination (20 per page)
- Auto-refresh toggle (15s)
- Grouped view by source IP
- Total traffic summary

### 4. Router Network Connections (`/monitor_router/<id>` connections tab)
- Internal IP addresses organized by interface
- Connected DHCP clients per subnet
- Upstream routing info (default gateway, bridge parent, or direct WAN)

### 5. System Logs (`/router_logs/<id>`)
- Paginated log viewing (50 per page)
- Filter by severity (critical, warning, error, info, debug, other)
- Full-text search across messages
- Log statistics by category and severity
- Configurable retention (1/3/7/30/90 days)
- CSV export with filters
- Auto-cleanup of old logs

### 6. Authentication
- Default credentials: `admin` / `admin`
- Password hashed with SHA-256
- Change password functionality
- Session-based authentication

## Database Schema

All stored in `data/routers.db`:

| Table | Purpose |
|-------|---------|
| `routers` | Router credentials (name, host, port, username, password) |
| `users` | Application users (username, password_hash) |
| `router_status_cache` | Cached online/offline status + router info JSON |
| `ip_bandwidth_data` | Per-IP traffic history (ip, mac, hostname, rx_bytes, tx_bytes, timestamp) |
| `interface_bandwidth_data` | Per-interface traffic history (interface_name, rx_bytes, tx_bytes, timestamp) |
| `router_logs` | Stored system logs (timestamp, topics, message, severity) |
| `log_retention_settings` | Per-router retention config (default: 7 days) |

## Key API Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Dashboard (list routers with status) |
| `/add_router` | GET/POST | Add new router (tests connection first) |
| `/delete_router/<id>` | GET | Remove router |
| `/refresh_router/<id>` | GET | Refresh single router status |
| `/monitor_router/<id>` | GET | Detailed monitoring page |
| `/connections/<id>` | GET | Live firewall connections page |
| `/router_logs/<id>` | GET | System logs with pagination |
| `/api/monitor/<id>` | GET | JSON endpoint for monitor data |
| `/api/connections/<id>` | GET | JSON endpoint for connections |
| `/api/connection-count/<id>` | GET | JSON endpoint for connection count |
| `/api/chart/bandwidth/<id>` | GET | Per-IP bandwidth chart data |
| `/api/chart/interface_bandwidth/<id>` | GET | Interface bandwidth chart data |
| `/api/network-connections/<id>` | GET | Network connections JSON |
| `/export_logs_csv/<id>` | GET | Export logs as CSV |
| `/update_log_retention/<id>` | POST | Update log retention settings |
| `/login` | GET/POST | Login |
| `/logout` | GET | Logout |
| `/change_password` | GET/POST | Change password |

## Architecture

### Connection Pattern (stable, tested on 1000+ routers)

```python
from routeros_api import RouterOsApiPool

connection = RouterOsApiPool(
    host=router.ip,
    username=router.username,
    password=router.password,
    port=8728,
    use_ssl=False,
    plaintext_login=True
)
api = connection.get_api()
# ... use api ...
connection.disconnect()
```

### Background Collector (`bandwidth_collector.py`)
- Runs alongside the Flask app (started by `start.sh`)
- Collects per-IP and per-interface bandwidth data every 60 seconds
- Collects router logs every 5 minutes
- Imports data into `ip_bandwidth_data` and `interface_bandwidth_data` tables
- Respects status cache (skips offline routers)

### Firewall Connection Caching
- 10-second TTL cache (`firewall_connections_cache` dict)
- Thread-safe with lock
- Processes `/ip/firewall/connection` data to extract internal→external traffic
- Classifies internal vs external IPs using prefix matching (`192.168.`, `10.`, `172.16-31.`)
- Maps hostnames via DHCP leases and ARP table
- Parses RouterOS duration format (`2h15m30s`)
- Identifies services by destination port (40+ common ports mapped)

### Templates (Jinja2)
| Template | Description |
|----------|-------------|
| `base.html` | Main layout with navbar, session handling, JS/CSS includes |
| `login.html` | Login form |
| `index.html` | Dashboard with router cards (status, CPU, memory, uptime) |
| `add_router.html` | Add/edit router form |
| `monitor.html` | Detailed router monitor with tabs (system, addresses, DHCP, ARP, health, logs, charts) |
| `connections.html` | Live connections table with auto-refresh, sorting, grouping |
| `router_logs.html` | Paginated logs with filters, retention config, CSV export |
| `change_password.html` | Password change form |
| `error.html` | Error display |

## Running

### Docker (recommended)
```bash
docker-compose up -d
# Access at http://localhost:8080
```

### Manual
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./start.sh  # inits DB, starts collector + Flask
# Access at http://localhost:8080
```

### Files
```bash
./run.sh        # Quick start (Flask only)
./setup.sh      # Install dependencies
./restart-app.sh # Restart
```

## Performance Optimizations

1. **Simple IP classification**: Pre-compiled network range tuples instead of regex
2. **Batch database operations**: `executemany()` for bulk inserts
3. **Early filtering**: Skip invalid connections during parsing
4. **Connection caching**: 10s TTL for firewall connections
5. **Status caching**: Router status cached to avoid repeated failed connections
6. **Graceful degradation**: If bandwidth data is empty, generates sample data for testing
7. **Multiple field fallbacks**: Handles different RouterOS versions by trying multiple field names

## Critical Stability Rules

- Use `RouterOsApiPool` with exact parameter names (`host`, `port`, `username`, `password`, `plaintext_login`, `use_ssl`)
- Always call `.disconnect()` after using RouterOS connections
- Use simple `.get()` method — no `.call('print', {...})` (unsupported)
- Handle field name variations across RouterOS versions (v6 vs v7)
- Never pass unsupported parameters like `timeout=` to `.get()`

## Development

Add routers via the web UI at `http://localhost:8080/add_router`. The MikroTik router must have the API service enabled (`/ip/service enable api`). A read-only user is recommended.
