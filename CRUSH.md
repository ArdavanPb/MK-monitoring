# MK-Monitoring Commands and Setup

## Development Commands
- **Start Flask app**: `venv/bin/python app.py`
- **Start bandwidth collector**: `venv/bin/python bandwidth_collector.py`
- **Run both services**: Use Docker Compose with `docker-compose up`
- **Docker troubleshooting**: If getting `OperationalError: no such table: routers`, rebuild with `docker-compose build --no-cache`

## Dependencies
- Flask==2.3.3
- routeros-api==0.18
- schedule==1.2.1

## Database
- **Database path**: `/app/data/routers.db` (persistent storage)
- **Tables**: 
  - `routers`: Router connection information
  - `ip_bandwidth_data`: Per-IP bandwidth monitoring data
  - `router_status_cache`: Router status cache for faster dashboard loading
- **Database initialization**: Both `app.py` and `bandwidth_collector.py` include database initialization to prevent `OperationalError: no such table` errors

## Features
- **Per-IP bandwidth monitoring**: Tracks data volume in megabytes every minute for internal IPs only
- **Zabbix-style time period filter**: Dropdown to select time period (1m, 5m, 15m, 30m, 1h, 3h, 6h, 12h, 24h, 3d, 1w)
- **Single table view**: Shows only one time period at a time, like Zabbix
- **Clean IP display**: Shows only IP addresses without ports or MAC addresses
- **Megabyte display**: Upload (MB), Download (MB), and Total (MB) columns
- **Internal IP filtering**: Only shows data for DHCP leases and static IPs
- **User password management**: Users can change their passwords via the web interface
- **Table scroll limits**: Tables display maximum 10 rows with scroll bars for larger datasets

## Code Style
- Flask application with SQLite database
- RouterOS API for MikroTik communication
- Bootstrap-based web interface
- Background data collection every minute
- **Template-based architecture**: All HTML in templates, no embedded HTML in Python files