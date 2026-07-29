#!/usr/bin/env python3
"""
Alert Engine for MK-Monitoring.
Evaluates alert rules every 30 seconds and sends notifications.
Supports email (SMTP), webhook (HTTP POST), and syslog actions.
Uses separate database connection from other collectors.
"""
import sqlite3
import json
import os
import time
import signal
import smtplib
import logging
import urllib.request
import urllib.error
from email.message import EmailMessage
from datetime import datetime
from logging.handlers import SysLogHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s ALERT %(levelname)s: %(message)s')
logger = logging.getLogger('alert_engine')

running = True

def signal_handler(sig, frame):
    global running
    logger.info("Received SIGTERM, shutting down gracefully...")
    running = False

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

db_path = os.environ.get('DB_PATH', 'data/routers.db')
if not os.path.exists(os.path.dirname(db_path)):
    db_path = 'data/routers.db'

# Email config from environment
SMTP_HOST = os.environ.get('ALERT_SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('ALERT_SMTP_PORT', '587'))
SMTP_USER = os.environ.get('ALERT_SMTP_USER', '')
SMTP_PASS = os.environ.get('ALERT_SMTP_PASS', '')
SMTP_FROM = os.environ.get('ALERT_SMTP_FROM', '')
SMTP_TO = os.environ.get('ALERT_SMTP_TO', '')

def get_db():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_tables():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
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
        )
    ''')
    c.execute('''
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
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_alert_events_router ON alert_events (router_id, status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_alert_events_rule ON alert_events (rule_id)')
    conn.commit()
    conn.close()

def send_email(subject, body):
    if not SMTP_HOST:
        logger.warning("SMTP not configured, cannot send email alert")
        return False
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_FROM
        msg['To'] = SMTP_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        logger.info(f"Email alert sent: {subject}")
        return True
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False

def send_webhook(url, payload):
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=10)
        logger.info(f"Webhook posted to {url}")
        return True
    except Exception as e:
        logger.error(f"Webhook failed: {e}")
        return False

def send_syslog(message):
    try:
        handler = SysLogHandler(address='/dev/log')
        handler.emit(logging.LogRecord('alert', logging.WARNING, '', 0, message, None, None))
        handler.close()
        return True
    except Exception:
        try:
            handler = SysLogHandler(address=('localhost', 514))
            handler.emit(logging.LogRecord('alert', logging.WARNING, '', 0, message, None, None))
            handler.close()
            return True
        except Exception as e:
            logger.error(f"Syslog failed: {e}")
            return False

def fire_action(rule, message):
    """Execute the action configured in the rule"""
    action_config = json.loads(rule['action_config']) if isinstance(rule['action_config'], str) else rule.get('action_config', {})
    
    if rule['action'] == 'email':
        send_email(f"Alert: {rule['metric_type']} on router {rule['router_id']}", message)
    elif rule['action'] == 'webhook':
        url = action_config.get('url', '')
        if url:
            send_webhook(url, {'alert': rule['metric_type'], 'router_id': rule['router_id'], 'message': message, 'time': str(datetime.now())})
    elif rule['action'] == 'syslog':
        send_syslog(message)

def evaluate_cpu(rule, conn):
    """Check CPU against threshold using SNMP metrics"""
    c = conn.cursor()
    c.execute('''
        SELECT cpu_percent FROM snmp_system_metrics
        WHERE router_id = ? ORDER BY timestamp DESC LIMIT 1
    ''', (rule['router_id'],))
    row = c.fetchone()
    if row and row['cpu_percent'] is not None:
        val = row['cpu_percent']
        threshold = float(rule['threshold_value'])
        if rule['condition'] == 'gt' and val > threshold:
            return True, f"CPU at {val:.1f}% (threshold: >{threshold}%)"
        if rule['condition'] == 'lt' and val < threshold:
            return True, f"CPU at {val:.1f}% (threshold: <{threshold}%)"
    return False, None

def evaluate_memory(rule, conn):
    """Check memory usage against threshold using SNMP metrics"""
    c = conn.cursor()
    c.execute('''
        SELECT memory_used, memory_total FROM snmp_system_metrics
        WHERE router_id = ? AND memory_total IS NOT NULL AND memory_total > 0
        ORDER BY timestamp DESC LIMIT 1
    ''', (rule['router_id'],))
    row = c.fetchone()
    if row:
        pct = (row['memory_used'] / row['memory_total']) * 100
        threshold = float(rule['threshold_value'])
        if rule['condition'] == 'gt' and pct > threshold:
            return True, f"Memory at {pct:.1f}% (threshold: >{threshold}%)"
        if rule['condition'] == 'lt' and pct < threshold:
            return True, f"Memory at {pct:.1f}% (threshold: <{threshold}%)"
    return False, None

def evaluate_interface_down(rule, conn):
    """Check if any interface is down using SNMP ifOperStatus"""
    # This is evaluated via SNMP - we check the latest interface metrics
    # If an interface has 0 rx and 0 tx for extended period, flag it
    c = conn.cursor()
    c.execute('''
        SELECT interface_name, rx_bytes, tx_bytes FROM snmp_interface_metrics
        WHERE router_id = ? ORDER BY timestamp DESC LIMIT 50
    ''', (rule['router_id'],))
    rows = c.fetchall()
    if len(rows) < 2:
        return False, None
    
    # Group by interface, check if any has all zeros
    from collections import defaultdict
    iface_data = defaultdict(list)
    for r in rows:
        iface_data[r['interface_name']].append((r['rx_bytes'], r['tx_bytes']))
    
    for iface, points in iface_data.items():
        if len(points) >= 2:
            latest_rx, latest_tx = points[-1]
            if latest_rx == 0 and latest_tx == 0:
                return True, f"Interface {iface} appears down (0 traffic)"
    return False, None

def evaluate_connections(rule, conn):
    """Check connection count using the firewall_connections_cache"""
    c = conn.cursor()
    c.execute('''
        SELECT COUNT(*) as cnt FROM (
            SELECT src_ip FROM ip_bandwidth_data
            WHERE router_id = ? AND timestamp >= datetime('now', '-5 minutes')
            GROUP BY src_ip
        )
    ''', (rule['router_id'],))
    row = c.fetchone()
    if row:
        threshold = int(rule['threshold_value'])
        if rule['condition'] == 'gt' and row[0] > threshold:
            return True, f"Active connections: {row[0]} (threshold: >{threshold})"
        if rule['condition'] == 'lt' and row[0] < threshold:
            return True, f"Active connections: {row[0]} (threshold: <{threshold})"
    return False, None

def evaluate_log_match(rule, conn):
    """Check router_logs for matching patterns"""
    c = conn.cursor()
    c.execute('''
        SELECT message FROM router_logs
        WHERE router_id = ? AND stored_at >= datetime('now', '-5 minutes')
        ORDER BY stored_at DESC LIMIT 50
    ''', (rule['router_id'],))
    rows = c.fetchall()
    for row in rows:
        if rule['condition'] == 'contains' and rule['threshold_value'].lower() in row['message'].lower():
            return True, f"Log matched: {row['message'][:200]}"
        if rule['condition'] == 'eq' and row['message'] == rule['threshold_value']:
            return True, f"Log matched: {row['message'][:200]}"
    return False, None

def check_rules():
    """Evaluate all enabled alert rules"""
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute('SELECT id FROM alert_rules LIMIT 1')
    except sqlite3.OperationalError:
        conn.close()
        return
    
    c.execute('SELECT * FROM alert_rules WHERE enabled = 1')
    rules = c.fetchall()
    
    now = datetime.now()
    
    for rule in rules:
        triggered = False
        message = None
        
        if rule['metric_type'] == 'cpu':
            triggered, message = evaluate_cpu(rule, conn)
        elif rule['metric_type'] == 'memory':
            triggered, message = evaluate_memory(rule, conn)
        elif rule['metric_type'] == 'interface_down':
            triggered, message = evaluate_interface_down(rule, conn)
        elif rule['metric_type'] == 'connections':
            triggered, message = evaluate_connections(rule, conn)
        elif rule['metric_type'] == 'log_match':
            triggered, message = evaluate_log_match(rule, conn)
        
        if triggered:
            # Check if already active to avoid duplicate alerts
            c.execute('''
                SELECT id FROM alert_events
                WHERE rule_id = ? AND status = 'active'
            ''', (rule['id'],))
            existing = c.fetchone()
            
            if not existing:
                c.execute('''
                    INSERT INTO alert_events (rule_id, router_id, status, message)
                    VALUES (?, ?, 'active', ?)
                ''', (rule['id'], rule['router_id'], message))
                conn.commit()
                fire_action(rule, message)
        else:
            # Resolve any active alerts for this rule
            c.execute('''
                UPDATE alert_events SET status = 'resolved', resolved_at = ?
                WHERE rule_id = ? AND status = 'active'
            ''', (now, rule['id']))
            conn.commit()
    
    conn.close()

if __name__ == '__main__':
    logger.info("Alert Engine started")
    ensure_tables()
    
    while running:
        try:
            check_rules()
        except Exception as e:
            logger.error(f"Alert check error: {e}")
        
        # Wait 30 seconds with graceful shutdown check
        for _ in range(30):
            if not running:
                break
            time.sleep(1)
    
    logger.info("Alert Engine stopped")
