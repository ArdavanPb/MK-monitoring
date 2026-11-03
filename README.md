# MikroTik Router Monitoring Application

A Flask application for MikroTik monitoring through RouterOS API, SNMP v2c, and NetFlow v5/v9 Traffic Flow exports.

## Features

- **Secure Credential Storage**: Router credentials are stored securely in a local SQLite database
- **Multiple Router Support**: Monitor multiple MikroTik routers from a single dashboard
- **Real-time Monitoring**: View router name, uptime, memory usage, CPU load, and firmware version
- **Detailed Monitoring**: Comprehensive system information including IP addresses, system identity, clock, and health data
- **Live Firewall Connections**: Sophos/FortiGate-style real-time connection monitoring with traffic analysis
- **Connection Testing**: Test router connections before adding them to the system
- **Custom API Port**: Support for custom MikroTik API ports (default: 8728)
- **Router Management**: Add, refresh, and delete routers from the dashboard
- **Real-time Connections**: View active network connections, connected clients, and upstream routes
- **Responsive Design**: Bootstrap-based responsive interface
- **Traffic Flow**: Receive NetFlow v5/v9 over UDP, browse all observed IPs with pagination, source/destination filters, upload/download ranking and per-IP charts
- **Freshness-aware Dashboard**: Distinguish current SNMP/Flow data from stale samples and show active alerts

## Quick Start

### Option 1: Docker (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd mk-monitoring

# Start the application
docker-compose up -d

# Access at http://localhost:8080
```

### Option 2: Manual Setup
```bash
# Clone the repository
git clone <repository-url>
cd mk-monitoring

# Run setup script (creates virtual environment and installs dependencies)
./setup.sh

# Start the app and all background collectors
./start.sh

# Access at http://localhost:8080
```

## Installation Details

### Docker Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd mk-monitoring
   ```

2. Build and run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

3. Open your browser and navigate to `http://localhost:8080`

### Manual Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd mk-monitoring
   ```

2. Install dependencies:
   ```bash
   # Using setup script (recommended)
   ./setup.sh
   
   # Or manually
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Configuration

### Traffic Flow setup

1. In **Add/Edit Router**, enable **Traffic Flow**. The exporter source IPv4 defaults to the router host; specify it when Flow packets use a different source address.
2. Point the MikroTik at the reachable IPv4 address of this application's server:

   ```routeros
   /ip traffic-flow set enabled=yes interfaces=all
   /ip traffic-flow target add dst-address=<SERVER_IP> port=2055 version=9
   ```

3. Allow UDP 2055 from the router to the server. Docker Compose publishes this port. `./start.sh` starts the collector on a manual installation. `./run.sh` starts Flask only.
4. Open **Traffic Flow** on the router card. The page shows last export time, 5-minute, 1-hour or 24-hour volume/rate, all observed IPs and protocols. The IP details page shows its Flow totals for the last hour. Recently observed local Flow IPs also appear in the network IP list even when API monitoring is unavailable.

The receiver accepts only enabled routers whose source IPv4 matches the configured exporter address. It supports **NetFlow v5 (IPv4) and v9 (IPv4/IPv6)**; IPFIX is not supported. After a collector restart, v9 data waits for the router to resend its templates. Flow volume is based on received exports, so lost UDP packets and router packet sampling lower the displayed totals. Historical Flow data is retained for seven days by default (`FLOW_RETENTION_DAYS`). RouterOS may export active flows later than their traffic occurred.

Environment settings: `FLOW_LISTEN_HOST` (default `0.0.0.0`), `FLOW_PORT` (default `2055`), and `FLOW_RETENTION_DAYS` (default `7`). When changing `FLOW_PORT` in Docker, change both the environment value and published UDP port in `docker-compose.yml`.

RouterOS [Traffic Flow documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/21102653/Traffic%2BFlow) describes the target settings and which traffic reaches the flow subsystem.
The receiver follows Cisco's [NetFlow v5/v9 export format](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html).

### Exploring IP traffic and charts

The Flow page lists **all observed source and destination IPs** in the selected
5-minute, 1-hour or 24-hour period, across pages of 50/100/200 entries. Sort by
upload, download, total volume or IP text. Exact Source and Destination filters
are combined with AND and apply before aggregation. IP search and the
sources-only/destinations-only view affect the endpoint table; summary and
protocol totals still describe the source/destination-filtered flows.
Upload is bytes sent by an IP, download is bytes received. Adding every IP's total
counts both ends of each flow, whereas the summary counts each record once.

Click an IP for its chart. Flow-enabled routers use stored Flow exports, even
when the RouterOS API is unavailable. Periods include **1 minute, 5 minutes and
30 minutes**, plus the existing longer windows. Charts cover the whole selected
window (up to about 120 Flow buckets) and show UTC receive-time average rates.
Missing exports are gaps, not proof of zero traffic. Delayed exports may produce
bursts; this is not a precise instantaneous wire-rate measurement. Routers without
Flow use API counter estimates, sampled about once per minute. Chart.js is bundled
locally, so the chart itself does not need a browser connection to a CDN.

Traffic Flow only sees traffic exported by the router; silent IPs, packets bypassing
its flow subsystem, missing templates and lost UDP exports cannot be discovered
from Flow alone. Use API discovery alongside Flow for inventory.

### SNMP setup

Enable SNMP v2c on the router and allow UDP 161 from this server. Enable SNMP on the router form and set the community and port. The collector runs every 60 seconds; the dashboard marks data stale after three minutes without a sample. Interface polling prefers 64-bit HC counters and falls back to 32-bit counters if unavailable. Install the `snmp` system package for manual deployments; Docker includes it.

### Router API Setup

Before using this application, ensure your MikroTik router has API access enabled:

1. Log into your MikroTik router via WinBox or WebFig
2. Go to **System > Users**
3. Create a new user or edit an existing one
4. Enable **API** and **Read** permissions (at minimum)
5. For enhanced security, consider creating a dedicated API user

### Application Setup

#### Docker Method
1. Run the application:
   ```bash
   docker-compose up -d
   ```
2. Open your browser and navigate to `http://localhost:8080`

#### Manual Method
1. Run the application:
   ```bash
   python app.py
   ```
2. Open your browser and navigate to `http://localhost:8080`

3. Click "Add Router" to add your first MikroTik router

## Authentication

- **First login**: username `admin`; a fresh installation generates a random password
  in `data/.bootstrap_password` (read locally with `sudo cat data/.bootstrap_password`).
  You can instead supply `DEFAULT_PASSWORD` before the first startup; Compose reads
  it from `.env` (see `.env.example`). Change it after login and remove the bootstrap
  password file. Existing installations keep their current account and password.
- The application requires login to access the dashboard and router management
- Users are stored in the SQLite database

## Usage

1. **Login**: Access the application and log in with your credentials
2. **Add Router**: Click "Add Router" and provide:
   - Display name (for your reference)
   - Router IP/hostname
   - API username
   - API password
   - Optional SNMP v2c settings and Traffic Flow exporter source IPv4

2. **View Dashboard**: The main dashboard shows all configured routers with:
   - Router name and identity
   - Uptime
   - Memory usage with visual progress bar
   - CPU load with color-coded status
   - Firmware version
   - Online/offline/unknown state, SNMP and Flow freshness, 5-minute Flow average, and active alerts

3. **Manage Routers**: 
   - Refresh individual router data
   - Delete routers you no longer want to monitor

## Security Notes

- Router and SNMP credentials are encrypted at rest using Fernet (AES-128) with a
  key persisted under the data directory (or supplied via `FERNET_KEY`)
- User passwords use Werkzeug salted password hashes (legacy SHA-256 hashes are upgraded on login)
- All state-changing requests are protected against CSRF
- Login attempts are rate-limited to prevent brute force
- This implementation connects to RouterOS API over unencrypted TCP; use a trusted management network or VPN
- Set `SECRET_KEY` in the environment for a stable session/CSRF signing key
- Consider running this application on a secure internal network
- Use dedicated API users with minimal required permissions
- Replace any legacy default password. See [SECURITY.md](SECURITY.md) for deployment and GitHub publication checks.

## API Information Retrieved

- System identity (router name)
- System resources (memory, CPU)
- Uptime
- Firmware version

## Dependencies

- **Flask**: Web framework
- **routeros-api**: Python library for MikroTik RouterOS API

## File Structure

```
mk-monitoring/
├── app.py              # Flask app factory + routes
├── config.py           # Environment-based configuration
├── db.py               # Database layer (schema, migrations, connections)
├── security.py         # Password hashing, encryption, CSRF, rate limiting
├── utils.py            # Formatting, parsing, IP classification helpers
├── routeros_client.py  # RouterOS API connectivity + data retrieval
├── services.py         # Business logic (bandwidth, connections, logs, backups)
├── snmp_collector.py   # Background SNMP metrics collector
├── bandwidth_collector.py # Background per-IP bandwidth collector
├── flow_collector.py    # NetFlow v5/v9 UDP receiver
├── netflow_v9.py        # NetFlow v9 template decoder
├── flow_service.py      # Flow summaries and per-IP queries
├── alert_engine.py     # Background alert rule evaluator
├── data/routers.db     # SQLite database (created automatically)
├── requirements.txt    # Python dependencies
├── templates/          # HTML templates
├── Dockerfile          # Docker container definition
├── docker-compose.yml  # Docker Compose configuration
├── setup.sh           # Manual setup script
├── start.sh           # Full manual stack (Flask and collectors)
├── run.sh             # Flask-only development script
└── README.md
```

## Development

For development and contributing, see [CONTRIBUTING.md](CONTRIBUTING.md).

### Development Commands

#### Docker Development
```bash
# Start with auto-rebuild
docker-compose up --build

# View logs
docker-compose logs -f

# Stop and cleanup
docker-compose down
```

#### Python Development
```bash
# Setup development environment
./setup.sh

# Run application
./run.sh

# Or run directly
source venv/bin/activate
python app.py
```

## Docker Commands

- **Start**: `docker-compose up -d`
- **Stop**: `docker-compose down`
- **View logs**: `docker-compose logs -f`
- **Rebuild**: `docker-compose up -d --build`
- **Check status**: `docker-compose ps`

### Browser cannot reach port 8080

Check `docker compose ps`: the service should show `0.0.0.0:8080->8080/tcp` in **PORTS**. A redirect from `http://localhost:8080/` to `/login` is normal.

If the container is healthy but **PORTS** is empty while `docker compose config` lists port 8080, inspect its Docker network. In one observed deployment, the container had no network endpoint; attaching it restored both browser access and the published ports:

```bash
docker network inspect mk-monitoring_mikrotik-monitor-network
docker network connect mk-monitoring_mikrotik-monitor-network mk-monitoring-mikrotik-monitor-1
docker compose ps
```

Use the network and container names reported on your host if they differ. If access works on `localhost` but not another device, use the host's LAN IP and check the host firewall. RouterOS API connectivity is separate from browser access.

## Database Storage

The application uses a SQLite database (WAL mode) at `data/routers.db` locally and
`/app/data/routers.db` inside the container. The Docker Compose setup mounts the
`./data` directory as a persistent volume, so data survives container restarts.

## Publishing and maintenance

See [SECURITY.md](SECURITY.md) before pushing to GitHub. Current design and file
structure live in [ARCHITECTURE.md](ARCHITECTURE.md); developer setup is in
[CONTRIBUTING.md](CONTRIBUTING.md). Historical duplicate feature notes and the unused
SQL migration script were removed; database migrations run through `db.init_db()`.
