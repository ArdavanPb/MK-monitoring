"""Database layer.

Single source of truth for the SQLite schema and migrations. All other modules
(Flask app, SNMP collector, alert engine) share this module so tables and
columns can never drift out of sync again.

Connections are opened with WAL journaling, a busy timeout, and foreign keys
enabled so multiple processes can safely read/write concurrently.
"""
import datetime as _datetime
import os
import sqlite3

import config


def _adapt_datetime(value):
    """Store datetimes as sortable 'YYYY-MM-DD HH:MM:SS' strings.

    The default sqlite3 datetime adapter is deprecated as of Python 3.12.
    Registering our own also keeps stored values consistent with the
    ``CURRENT_TIMESTAMP`` default and with the string thresholds used in
    queries.
    """
    return value.strftime("%Y-%m-%d %H:%M:%S")


sqlite3.register_adapter(_datetime.datetime, _adapt_datetime)

# Canonical table definitions. Kept in one place; migrations below add any
# columns that older databases may be missing.
_SCHEMA = {
    "routers": """
        CREATE TABLE IF NOT EXISTS routers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER DEFAULT 8728,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            snmp_enabled INTEGER DEFAULT 0,
            snmp_community TEXT DEFAULT 'public',
            snmp_version INTEGER DEFAULT 2,
            snmp_port INTEGER DEFAULT 161,
            snmp_user TEXT DEFAULT '',
            snmp_auth_protocol TEXT DEFAULT 'MD5',
            snmp_auth_pass TEXT DEFAULT '',
            snmp_priv_protocol TEXT DEFAULT 'DES',
            snmp_priv_pass TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "users": """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "ip_bandwidth_data": """
        CREATE TABLE IF NOT EXISTS ip_bandwidth_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            rx_bytes INTEGER DEFAULT 0,
            tx_bytes INTEGER DEFAULT 0,
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "interface_bandwidth_data": """
        CREATE TABLE IF NOT EXISTS interface_bandwidth_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            interface_name TEXT NOT NULL,
            rx_bytes INTEGER DEFAULT 0,
            tx_bytes INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "router_status_cache": """
        CREATE TABLE IF NOT EXISTS router_status_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            router_info TEXT,
            source_type TEXT DEFAULT 'API',
            snmp_port INTEGER,
            api_port INTEGER,
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "router_logs": """
        CREATE TABLE IF NOT EXISTS router_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            topics TEXT,
            message TEXT NOT NULL,
            severity TEXT,
            stored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "log_retention_settings": """
        CREATE TABLE IF NOT EXISTS log_retention_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            retention_days INTEGER DEFAULT 7,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "snmp_system_metrics": """
        CREATE TABLE IF NOT EXISTS snmp_system_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu_percent REAL,
            memory_used INTEGER,
            memory_total INTEGER,
            uptime_seconds INTEGER,
            temperature_celsius REAL,
            cpu_cores INTEGER,
            board_name TEXT,
            architecture TEXT,
            platform TEXT,
            firmware TEXT,
            router_name TEXT,
            source_type TEXT DEFAULT 'SNMP',
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "snmp_interface_metrics": """
        CREATE TABLE IF NOT EXISTS snmp_interface_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            interface_name TEXT NOT NULL,
            ifindex INTEGER,
            rx_bytes INTEGER DEFAULT 0,
            tx_bytes INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "alert_rules": """
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            metric_type TEXT NOT NULL CHECK(metric_type IN ('cpu','memory','interface_down','connections','log_match')),
            condition TEXT NOT NULL CHECK(condition IN ('gt','lt','eq','contains')),
            threshold_value TEXT NOT NULL,
            duration_seconds INTEGER DEFAULT 0,
            action TEXT NOT NULL CHECK(action IN ('email','webhook','syslog')),
            action_config TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "alert_events": """
        CREATE TABLE IF NOT EXISTS alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER NOT NULL,
            router_id INTEGER NOT NULL,
            triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME,
            status TEXT DEFAULT 'active' CHECK(status IN ('active','acknowledged','resolved')),
            message TEXT,
            FOREIGN KEY(rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
            FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
        )
    """,
    "audit_log": """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            request_body TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
}

# Column migrations applied idempotently for databases created before the
# column existed. Each entry is (table, column, definition).
_COLUMN_MIGRATIONS = [
    ("routers", "snmp_enabled", "INTEGER DEFAULT 0"),
    ("routers", "snmp_community", "TEXT DEFAULT 'public'"),
    ("routers", "snmp_version", "INTEGER DEFAULT 2"),
    ("routers", "snmp_port", "INTEGER DEFAULT 161"),
    ("routers", "snmp_user", "TEXT DEFAULT ''"),
    ("routers", "snmp_auth_protocol", "TEXT DEFAULT 'MD5'"),
    ("routers", "snmp_auth_pass", "TEXT DEFAULT ''"),
    ("routers", "snmp_priv_protocol", "TEXT DEFAULT 'DES'"),
    ("routers", "snmp_priv_pass", "TEXT DEFAULT ''"),
    ("users", "role", "TEXT DEFAULT 'viewer'"),
    ("router_status_cache", "router_info", "TEXT"),
    ("router_status_cache", "source_type", "TEXT DEFAULT 'API'"),
    ("router_status_cache", "snmp_port", "INTEGER"),
    ("router_status_cache", "api_port", "INTEGER"),
    ("snmp_system_metrics", "cpu_cores", "INTEGER"),
    ("snmp_system_metrics", "board_name", "TEXT"),
    ("snmp_system_metrics", "architecture", "TEXT"),
    ("snmp_system_metrics", "platform", "TEXT"),
    ("snmp_system_metrics", "firmware", "TEXT"),
    ("snmp_system_metrics", "router_name", "TEXT"),
    ("snmp_system_metrics", "source_type", "TEXT DEFAULT 'SNMP'"),
]

_INDEXES = {
    "idx_ip_bandwidth_router_time": "ip_bandwidth_data(router_id,timestamp)",
    "idx_ip_bandwidth_ip": "ip_bandwidth_data(ip_address)",
    "idx_ip_bandwidth_mac": "ip_bandwidth_data(mac_address)",
    "idx_router_status_time": "router_status_cache(last_checked)",
    "idx_router_logs_time": "router_logs(router_id,timestamp)",
    "idx_router_logs_severity": "router_logs(severity)",
    "idx_snmp_system_router_time": "snmp_system_metrics(router_id,timestamp)",
    "idx_snmp_interface_router_time": "snmp_interface_metrics(router_id,timestamp)",
    "idx_alert_events_router": "alert_events(router_id,status)",
    "idx_alert_events_rule": "alert_events(rule_id)",
    "idx_audit_log_time": "audit_log(created_at)",
}


def get_connection():
    """Open a configured SQLite connection.

    The caller is responsible for closing it.
    """
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _column_exists(conn, table, column):
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def init_db():
    """Create/upgrade the schema and seed default data. Idempotent."""
    os.makedirs(config.DATA_DIR, exist_ok=True)
    conn = get_connection()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        for ddl in _SCHEMA.values():
            conn.execute(ddl)

        for table, column, definition in _COLUMN_MIGRATIONS:
            if not _column_exists(conn, table, column):
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                )

        for name, definition in _INDEXES.items():
            conn.execute(
                f"CREATE INDEX IF NOT EXISTS {name} ON {definition}"
            )

        _seed_default_user(conn)
        conn.commit()
    finally:
        conn.close()


def _seed_default_user(conn):
    from security import hash_password

    conn.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (config.DEFAULT_USERNAME, hash_password(config.DEFAULT_PASSWORD), "admin"),
    )
    # Ensure the default admin account always holds the admin role.
    conn.execute(
        "UPDATE users SET role='admin' WHERE username=? AND (role IS NULL OR role='viewer')",
        (config.DEFAULT_USERNAME,),
    )
