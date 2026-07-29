-- Migration: Add SNMP fields, alert tables, audit log, user roles
-- Run: sqlite3 data/routers.db < migration.sql

-- SNMP fields for routers
ALTER TABLE routers ADD COLUMN snmp_enabled INTEGER DEFAULT 0;
ALTER TABLE routers ADD COLUMN snmp_community TEXT DEFAULT 'public';
ALTER TABLE routers ADD COLUMN snmp_version INTEGER DEFAULT 2;
ALTER TABLE routers ADD COLUMN snmp_port INTEGER DEFAULT 161;
ALTER TABLE routers ADD COLUMN snmp_user TEXT DEFAULT '';
ALTER TABLE routers ADD COLUMN snmp_auth_protocol TEXT DEFAULT 'MD5';
ALTER TABLE routers ADD COLUMN snmp_auth_pass TEXT DEFAULT '';
ALTER TABLE routers ADD COLUMN snmp_priv_protocol TEXT DEFAULT 'DES';
ALTER TABLE routers ADD COLUMN snmp_priv_pass TEXT DEFAULT '';

-- Role field for users
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer';

-- Update default admin to admin
UPDATE users SET role = 'admin' WHERE username = 'admin';

-- SNMP system metrics
CREATE TABLE IF NOT EXISTS snmp_system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    cpu_percent REAL,
    memory_used INTEGER,
    memory_total INTEGER,
    uptime_seconds INTEGER,
    temperature_celsius REAL,
    FOREIGN KEY (router_id) REFERENCES routers (id)
);

-- SNMP interface metrics
CREATE TABLE IF NOT EXISTS snmp_interface_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    interface_name TEXT NOT NULL,
    ifindex INTEGER,
    rx_bytes INTEGER DEFAULT 0,
    tx_bytes INTEGER DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (router_id) REFERENCES routers (id)
);

-- Alert rules
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
    FOREIGN KEY (router_id) REFERENCES routers (id)
);

-- Alert events
CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    router_id INTEGER NOT NULL,
    triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    status TEXT DEFAULT 'active' CHECK(status IN ('active','acknowledged','resolved')),
    message TEXT,
    FOREIGN KEY (rule_id) REFERENCES alert_rules (id),
    FOREIGN KEY (router_id) REFERENCES routers (id)
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    request_body TEXT,
    ip_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_snmp_system_router_time ON snmp_system_metrics (router_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_snmp_interface_router_time ON snmp_interface_metrics (router_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_events_router ON alert_events (router_id, status);
CREATE INDEX IF NOT EXISTS idx_alert_events_rule ON alert_events (rule_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log (created_at);

-- Migration v2: SNMP metadata fields and source tracking
ALTER TABLE snmp_system_metrics ADD COLUMN cpu_cores INTEGER;
ALTER TABLE snmp_system_metrics ADD COLUMN board_name TEXT;
ALTER TABLE snmp_system_metrics ADD COLUMN architecture TEXT;
ALTER TABLE snmp_system_metrics ADD COLUMN platform TEXT;
ALTER TABLE snmp_system_metrics ADD COLUMN firmware TEXT;
ALTER TABLE snmp_system_metrics ADD COLUMN router_name TEXT;
ALTER TABLE snmp_system_metrics ADD COLUMN source_type TEXT DEFAULT 'SNMP';

ALTER TABLE router_status_cache ADD COLUMN source_type TEXT DEFAULT 'API';
ALTER TABLE router_status_cache ADD COLUMN snmp_port INTEGER;
ALTER TABLE router_status_cache ADD COLUMN api_port INTEGER;
