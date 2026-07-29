#!/usr/bin/env python3
"""
SNMP collector for MikroTik routers.
Polls SNMP-enabled routers every 60 seconds for system and interface metrics.
Uses snmpget/snmpwalk CLI tools (no native library dependencies).
"""
import sqlite3
import time
import os
import signal
import sys
import logging
import subprocess
import re
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s SNMP %(levelname)s: %(message)s')
logger = logging.getLogger('snmp_collector')

running = True

def signal_handler(sig, frame):
    global running
    logger.info("Received SIGTERM, shutting down gracefully...")
    running = False

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

db_path = os.environ.get('DB_PATH', 'data/routers.db')
if not os.path.exists(os.path.dirname(db_path) if os.path.dirname(db_path) else '.'):
    db_path = 'data/routers.db'

def get_db():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_tables():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
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
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS snmp_interface_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id INTEGER NOT NULL,
            interface_name TEXT NOT NULL,
            ifindex INTEGER,
            rx_bytes INTEGER DEFAULT 0,
            tx_bytes INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (router_id) REFERENCES routers (id)
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_snmp_system_router_time ON snmp_system_metrics (router_id, timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_snmp_interface_router_time ON snmp_interface_metrics (router_id, timestamp)')
    # Add new columns if missing (graceful migration)
    for col,typ in [('cpu_cores','INTEGER'),('board_name','TEXT'),('architecture','TEXT'),('platform','TEXT'),('firmware','TEXT'),('router_name','TEXT'),('source_type',"TEXT DEFAULT 'SNMP'")]:
        try: c.execute(f"ALTER TABLE snmp_system_metrics ADD COLUMN {col} {typ}")
        except: pass
    for col,typ in [('source_type',"TEXT DEFAULT 'API'"),('snmp_port','INTEGER'),('api_port','INTEGER')]:
        try: c.execute(f"ALTER TABLE router_status_cache ADD COLUMN {col} {typ}")
        except: pass
    conn.commit()
    conn.close()

def snmp_version_str(version):
    """Convert numeric version to CLI-compatible version string"""
    return '2c' if version == 2 else str(version)

def snmp_get(host, community, oid, version=2, port=161):
    """Get a single OID value via snmpget CLI, returns raw string value"""
    ver = snmp_version_str(version)
    cmd = ['snmpget', '-v', ver, '-c', community, '-t', '5', '-r', '1', '-OQv', f'{host}:{port}', oid]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            val = result.stdout.strip()
            return val if val else None
        logger.warning(f"snmp_get rc={result.returncode} for {oid} on {host}:{port}: {result.stderr.strip()[:200]}")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"snmp_get timeout for {oid}")
        return None
    except FileNotFoundError:
        logger.error("snmpget not found. Install: apt-get install snmp")
        return None
    except Exception as e:
        logger.warning(f"snmp_get exception for {oid}: {e}")
        return None

def snmp_get_int(host, community, oid, version=2, port=161):
    """Get a single integer OID value, stripping non-numeric suffixes"""
    raw = snmp_get(host, community, oid, version, port)
    if raw is None:
        return None
    # Strip common suffixes like " KBytes", " Bytes", etc.
    import re
    match = re.search(r'(-?\d+)', raw)
    if match:
        return int(match.group(1))
    return None

def snmp_get_float(host, community, oid, version=2, port=161):
    """Get a single float OID value"""
    raw = snmp_get(host, community, oid, version, port)
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        import re
        match = re.search(r'(-?\d+\.?\d*)', raw)
        if match:
            return float(match.group(1))
        return None

def snmp_walk(host, community, oid, version=2, port=161):
    """Walk an OID tree via snmpwalk CLI, returns list of (suffix, value)"""
    ver = snmp_version_str(version)
    cmd = ['snmpwalk', '-v', ver, '-c', community, '-t', '5', '-r', '1', '-OQ', f'{host}:{port}', oid]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            entries = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line or ' = ' not in line:
                    continue
                oid_part, val = line.split(' = ', 1)
                suffix = oid_part.split('.')[-1]
                entries.append((suffix, val.strip()))
            return entries
        return []
    except Exception as e:
        logger.warning(f"snmp_walk failed for {oid}: {e}")
        return []

def poll_snmp_router(router_id, host, community, version, port):
    """Poll a router via SNMP CLI tools and store results"""
    try:
        now = datetime.now()
        
        # Quick connectivity test
        uptime_raw = snmp_get(host, community, '.1.3.6.1.2.1.1.3.0', version, port)
        if uptime_raw is None:
            logger.warning(f"Router {router_id}: SNMP connectivity test failed (no response from {host}:{port})")
            return False
        
        # System uptime parsing
        uptime_seconds = None
        try:
            if uptime_raw.isdigit():
                uptime_seconds = int(uptime_raw) // 100
            else:
                parts = uptime_raw.split(':')
                if len(parts) == 4:
                    d, h, m, s = parts
                    uptime_seconds = int(d) * 86400 + int(h) * 3600 + int(m) * 60 + int(float(s))
                elif len(parts) == 3:
                    h, m, s = parts
                    uptime_seconds = int(h) * 3600 + int(m) * 60 + int(float(s))
        except Exception:
            pass
        
        # CPU load (MikroTik OID)
        cpu_value = snmp_get_float(host, community, '.1.3.6.1.4.1.14988.1.1.3.1.0', version, port)
        
        # Memory (MikroTik OIDs: total and free in bytes)
        memory_total = snmp_get_int(host, community, '.1.3.6.1.4.1.14988.1.1.4.1.0', version, port)
        free_memory = snmp_get_int(host, community, '.1.3.6.1.4.1.14988.1.1.4.2.0', version, port)
        memory_used = None
        if memory_total and free_memory:
            memory_used = memory_total - free_memory
        
        # Temperature
        temperature = None
        for temp_oid in ['.1.3.6.1.4.1.14988.1.1.3.10.0', '.1.3.6.1.2.1.99.1.1.1.4.1']:
            t = snmp_get_float(host, community, temp_oid, version, port)
            if t is not None:
                temperature = t
                break
        
        # MikroTik-specific SNMP metadata
        router_name = snmp_get(host, community, '.1.3.6.1.4.1.14988.1.1.1.1.0', version, port)
        board_name = snmp_get(host, community, '.1.3.6.1.4.1.14988.1.1.1.2.0', version, port)
        firmware = snmp_get(host, community, '.1.3.6.1.4.1.14988.1.1.1.3.0', version, port)
        platform = snmp_get(host, community, '.1.3.6.1.4.1.14988.1.1.1.4.0', version, port)
        architecture = snmp_get(host, community, '.1.3.6.1.4.1.14988.1.1.1.5.0', version, port)
        cpu_cores = snmp_get_int(host, community, '.1.3.6.1.4.1.14988.1.1.3.2.0', version, port)
        
        # Strip quotes from text values
        if router_name: router_name = router_name.strip('"')
        if board_name: board_name = board_name.strip('"')
        if firmware: firmware = firmware.strip('"')
        if platform: platform = platform.strip('"')
        if architecture: architecture = architecture.strip('"')
        
        # Store system metrics with all new fields
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO snmp_system_metrics (router_id, timestamp, cpu_percent, memory_used, memory_total, uptime_seconds, temperature_celsius, cpu_cores, board_name, architecture, platform, firmware, router_name, source_type)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (router_id, now, cpu_value, memory_used, memory_total, uptime_seconds, temperature,
                  cpu_cores, board_name, architecture, platform, firmware, router_name, 'SNMP'))
        
        # Build SNMP info dict for cache
        import json
        snmp_info = {
            'name': router_name or f'Router {router_id}',
            'uptime': f'{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m' if uptime_seconds else 'N/A',
            'total_memory': str(memory_total) if memory_total else 'N/A',
            'free_memory': str(free_memory) if free_memory else 'N/A',
            'used_memory': str(memory_used) if memory_used else 'N/A',
            'memory_usage_percent': round(float(memory_used) / float(memory_total) * 100, 1) if (memory_used and memory_total and memory_total > 0) else 'N/A',
            'cpu_load': str(int(cpu_value)) if cpu_value is not None else 'N/A',
            'cpu_count': str(cpu_cores) if cpu_cores else 'N/A',
            'version': firmware or 'via SNMP',
            'board_name': board_name or 'N/A',
            'architecture_name': architecture or 'N/A',
        }
        # Update router_status_cache for dashboard reads
        try:
            c.execute('''INSERT OR REPLACE INTO router_status_cache (router_id,status,last_checked,router_info,source_type,snmp_port)
                         VALUES (?,?,?,?,?,?)''',
                      (router_id, 'online', now, json.dumps(snmp_info), 'SNMP', port))
        except Exception as e:
            logger.warning(f"Failed to update cache for router {router_id}: {e}")
        conn.commit()
        
        # Poll interfaces
        if_names = snmp_walk(host, community, '.1.3.6.1.2.1.2.2.1.2', version, port)   # ifDescr
        if_indexes = snmp_walk(host, community, '.1.3.6.1.2.1.2.2.1.1', version, port)  # ifIndex
        if_in = snmp_walk(host, community, '.1.3.6.1.2.1.2.2.1.10', version, port)      # ifInOctets
        if_out = snmp_walk(host, community, '.1.3.6.1.2.1.2.2.1.16', version, port)     # ifOutOctets
        
        # Build interface data
        name_map = {}
        for suffix, val in if_names:
            name_map[suffix] = val.strip('"')
        in_map = {}
        for suffix, val in if_in:
            try: in_map[suffix] = int(val)
            except: pass
        out_map = {}
        for suffix, val in if_out:
            try: out_map[suffix] = int(val)
            except: pass
        
        batch_data = []
        for suffix in name_map:
            try:
                if_num = int(suffix)
                batch_data.append((
                    router_id, name_map[suffix], if_num,
                    in_map.get(suffix, 0), out_map.get(suffix, 0), now
                ))
            except Exception:
                pass
        
        if batch_data:
            c.executemany('''INSERT INTO snmp_interface_metrics (router_id, interface_name, ifindex, rx_bytes, tx_bytes, timestamp)
                             VALUES (?, ?, ?, ?, ?, ?)''', batch_data)
        
        conn.commit()
        conn.close()
        
        logger.info(f"Router {router_id}: CPU={cpu_value}%, Mem={memory_used}/{memory_total}, Cores={cpu_cores}, Board={board_name}")
        return True
        
    except Exception as e:
        logger.error(f"Router {router_id} SNMP poll failed: {e}")
        return False

def collect_all():
    """Iterate all SNMP-enabled routers and poll them"""
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute("SELECT snmp_enabled FROM routers LIMIT 1")
    except sqlite3.OperationalError:
        conn.close()
        return
    
    c.execute('''SELECT id, name, host, snmp_community, snmp_version, snmp_port
                 FROM routers WHERE snmp_enabled = 1''')
    routers = c.fetchall()
    conn.close()
    
    for row in routers:
        if not running:
            break
        r = {'id': row[0], 'name': row[1], 'host': row[2],
             'community': row[3], 'version': row[4], 'port': row[5]}
        logger.info(f"Polling {r['name']} ({r['host']}) via SNMP v{r['version']}")
        poll_snmp_router(r['id'], r['host'], r['community'], r['version'], r['port'])

if __name__ == '__main__':
    logger.info("SNMP Collector started")
    ensure_tables()
    
    while running:
        try:
            collect_all()
        except Exception as e:
            logger.error(f"Collection cycle error: {e}")
        
        for _ in range(60):
            if not running:
                break
            time.sleep(1)
    
    logger.info("SNMP Collector stopped")
