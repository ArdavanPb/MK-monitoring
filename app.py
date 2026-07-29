from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from datetime import datetime
import routeros_api
import json
import os
import hashlib
import time
import threading
import math
import re
import subprocess
import glob
import traceback
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

logging_basic_config = {'level': 'INFO', 'format': '%(asctime)s APP %(levelname)s: %(message)s'}
import logging
logging.basicConfig(**logging_basic_config)
logger = logging.getLogger('app')

def format_bytes(size):
    if not size or size == 0: return "0 B"
    power = math.floor(math.log(size, 1024))
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    if power >= len(units): power = len(units) - 1
    return f"{size / (1024 ** power):.1f} {units[power]}"

def format_duration(seconds_str):
    if not seconds_str: return "N/A"
    try:
        seconds = int(''.join(filter(str.isdigit, seconds_str)))
        if seconds < 60: return f"{seconds}s"
        elif seconds < 3600: return f"{seconds // 60}m {seconds % 60}s"
        else: return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    except: return seconds_str

app.jinja_env.filters['format_bytes'] = format_bytes
app.jinja_env.filters['format_duration'] = format_duration

DEFAULT_USERNAME = 'admin'
DEFAULT_PASSWORD = 'admin'

db_path = os.environ.get('DB_PATH', '/app/data/routers.db')
firewall_connections_cache = {}
firewall_cache_lock = threading.Lock()
if not os.path.exists('/app/data'): db_path = 'data/routers.db'

def role_required(min_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.path.startswith('/api/'): return jsonify({'success': False, 'error': 'Auth required'}), 401
                return redirect(url_for('login'))
            user_role = session.get('role') or 'viewer'
            hierarchy = {'admin':3,'operator':2,'viewer':1}
            if hierarchy.get(user_role,0) < hierarchy.get(min_role,1):
                if request.path.startswith('/api/'): return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
                flash('No permission','error'); return redirect(url_for('index'))
            return f(*args,**kwargs)
        return decorated_function
    return decorator

def login_required(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'): return jsonify({'success': False, 'error': 'Auth required'}), 401
            return redirect(url_for('login'))
        return f(*args,**kwargs)
    return decorated_function

# ─── Safe API call helper ─────────────────────────────────────────────────

def safe_api_call(api, resource_path):
    """Call a RouterOS API resource and return {'data': ..., 'error': None} or {'data': None, 'error': '...'}"""
    try:
        resource = api.get_resource(resource_path)
        result = resource.get()
        if result is None:
            return {'data': None, 'error': f'{resource_path} returned None'}
        logger.info(f"API {resource_path}: got {len(result)} items, keys: {list(result[0].keys()) if result else 'empty'}")
        return {'data': result, 'error': None}
    except routeros_api.RouterOsApiConnectionError as e:
        logger.error(f"API {resource_path} connection error: {e}")
        return {'data': None, 'error': f'Connection error: {e}'}
    except Exception as e:
        logger.error(f"API {resource_path} error: {e}\n{traceback.format_exc()}")
        return {'data': None, 'error': str(e)}

def safe_api_call_single(api, resource_path):
    """Call API resource and return the first item as dict"""
    result = safe_api_call(api, resource_path)
    if result['error']:
        return {'data': {}, 'error': result['error']}
    items = result['data']
    if not items:
        return {'data': {}, 'error': f'{resource_path} returned empty list'}
    return {'data': items[0], 'error': None}

def test_snmp_connection(host, community, version, port):
    ver = '2c' if version == 2 else str(version)
    try:
        cmd = ['snmpget','-v',ver,'-c',community,'-t','5','-r','1','-OQv',f'{host}:{port}','.1.3.6.1.2.1.1.3.0']
        logger.info(f"Testing SNMP: {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        logger.info(f"SNMP test rc={r.returncode} stdout={r.stdout.strip()[:50]} stderr={r.stderr.strip()[:100]}")
        return r.returncode == 0
    except FileNotFoundError:
        logger.error("snmpget binary not found - install 'snmp' package (apt-get install snmp)")
        return False
    except Exception as e:
        logger.error(f"SNMP test error: {e}")
        return False

# ─── Audit log ────────────────────────────────────────────────────────────

@app.before_request
def audit_middleware():
    if request.method in ('POST','PUT','DELETE') and not request.path.startswith('/login') and 'user_id' in session:
        try:
            body = request.get_data(as_text=True)[:500] if request.get_data() else ''
            conn = sqlite3.connect(db_path); c = conn.cursor()
            c.execute('INSERT INTO audit_log (user_id,username,method,path,request_body,ip_address) VALUES (?,?,?,?,?,?)',
                     (session['user_id'],session.get('username',''),request.method,request.path,body,request.remote_addr))
            conn.commit(); conn.close()
        except: pass

# ─── Database init ────────────────────────────────────────────────────────

def init_db():
    global db_path
    os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
    try:
        conn = sqlite3.connect(db_path); c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS routers (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,host TEXT NOT NULL,port INTEGER DEFAULT 8728,username TEXT NOT NULL,password TEXT NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        for col,typ in [('snmp_enabled','INTEGER DEFAULT 0'),('snmp_community',"TEXT DEFAULT 'public'"),('snmp_version','INTEGER DEFAULT 2'),('snmp_port','INTEGER DEFAULT 161'),('snmp_user',"TEXT DEFAULT ''"),('snmp_auth_protocol',"TEXT DEFAULT 'MD5'"),('snmp_auth_pass',"TEXT DEFAULT ''"),('snmp_priv_protocol',"TEXT DEFAULT 'DES'"),('snmp_priv_pass',"TEXT DEFAULT ''")]:
            try: c.execute(f"ALTER TABLE routers ADD COLUMN {col} {typ}")
            except: pass
        c.execute('''CREATE TABLE IF NOT EXISTS ip_bandwidth_data (id INTEGER PRIMARY KEY AUTOINCREMENT,router_id INTEGER NOT NULL,ip_address TEXT NOT NULL,mac_address TEXT,hostname TEXT,timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,rx_bytes INTEGER DEFAULT 0,tx_bytes INTEGER DEFAULT 0,FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS router_status_cache (id INTEGER PRIMARY KEY AUTOINCREMENT,router_id INTEGER NOT NULL,status TEXT NOT NULL,last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,router_info TEXT,FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        try: c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer'")
        except: pass
        pw = hashlib.sha256(DEFAULT_PASSWORD.encode()).hexdigest()
        try: c.execute("INSERT OR IGNORE INTO users (username,password_hash,role) VALUES (?,?,?)",(DEFAULT_USERNAME,pw,'admin'))
        except: pass
        try: c.execute("SELECT router_info FROM router_status_cache LIMIT 1")
        except:
            try: c.execute("ALTER TABLE router_status_cache ADD COLUMN router_info TEXT")
            except: pass
        for col,typ in [('cpu_cores','INTEGER'),('board_name','TEXT'),('architecture','TEXT'),('platform','TEXT'),('source_type',"TEXT DEFAULT 'SNMP'")]:
            try: c.execute(f"ALTER TABLE snmp_system_metrics ADD COLUMN {col} {typ}")
            except: pass
        for col,typ in [('source_type',"TEXT DEFAULT 'API'"),('snmp_port','INTEGER'),('api_port','INTEGER')]:
            try: c.execute(f"ALTER TABLE router_status_cache ADD COLUMN {col} {typ}")
            except: pass
        c.execute('''CREATE TABLE IF NOT EXISTS router_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,router_id INTEGER NOT NULL,timestamp TEXT NOT NULL,topics TEXT,message TEXT NOT NULL,severity TEXT,stored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS interface_bandwidth_data (id INTEGER PRIMARY KEY AUTOINCREMENT,router_id INTEGER NOT NULL,interface_name TEXT NOT NULL,rx_bytes INTEGER DEFAULT 0,tx_bytes INTEGER DEFAULT 0,timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS log_retention_settings (id INTEGER PRIMARY KEY AUTOINCREMENT,router_id INTEGER NOT NULL,retention_days INTEGER DEFAULT 7,updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS snmp_system_metrics (id INTEGER PRIMARY KEY AUTOINCREMENT,router_id INTEGER NOT NULL,timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,cpu_percent REAL,memory_used INTEGER,memory_total INTEGER,uptime_seconds INTEGER,temperature_celsius REAL,FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS snmp_interface_metrics (id INTEGER PRIMARY KEY AUTOINCREMENT,router_id INTEGER NOT NULL,interface_name TEXT NOT NULL,ifindex INTEGER,rx_bytes INTEGER DEFAULT 0,tx_bytes INTEGER DEFAULT 0,timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS alert_rules (id INTEGER PRIMARY KEY AUTOINCREMENT,router_id INTEGER NOT NULL,metric_type TEXT NOT NULL,condition TEXT NOT NULL,threshold_value TEXT NOT NULL,duration_seconds INTEGER DEFAULT 0,action TEXT NOT NULL,action_config TEXT DEFAULT '{}',enabled INTEGER DEFAULT 1,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS alert_events (id INTEGER PRIMARY KEY AUTOINCREMENT,rule_id INTEGER NOT NULL,router_id INTEGER NOT NULL,triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,resolved_at DATETIME,status TEXT DEFAULT 'active',message TEXT,FOREIGN KEY(rule_id) REFERENCES alert_rules(id),FOREIGN KEY(router_id) REFERENCES routers(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,username TEXT,method TEXT NOT NULL,path TEXT NOT NULL,request_body TEXT,ip_address TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        for idx in ['idx_ip_bandwidth_router_time','idx_ip_bandwidth_ip','idx_ip_bandwidth_mac','idx_router_status_time','idx_router_logs_time','idx_router_logs_severity','idx_snmp_system_router_time','idx_snmp_interface_router_time','idx_alert_events_router','idx_alert_events_rule','idx_audit_log_time']:
            try: c.execute(f"CREATE INDEX IF NOT EXISTS {idx} ON { {'idx_ip_bandwidth_router_time':'ip_bandwidth_data(router_id,timestamp)','idx_ip_bandwidth_ip':'ip_bandwidth_data(ip_address)','idx_ip_bandwidth_mac':'ip_bandwidth_data(mac_address)','idx_router_status_time':'router_status_cache(last_checked)','idx_router_logs_time':'router_logs(router_id,timestamp)','idx_router_logs_severity':'router_logs(severity)','idx_snmp_system_router_time':'snmp_system_metrics(router_id,timestamp)','idx_snmp_interface_router_time':'snmp_interface_metrics(router_id,timestamp)','idx_alert_events_router':'alert_events(router_id,status)','idx_alert_events_rule':'alert_events(rule_id)','idx_audit_log_time':'audit_log(created_at)'}[idx]}")
            except: pass
        try: c.execute("UPDATE users SET role='admin' WHERE username='admin' AND (role IS NULL OR role='viewer')")
        except: pass
        conn.commit(); conn.close()
        logger.info(f"Database ready at {db_path}")
    except Exception as e:
        logger.error(f"Database init error: {e}"); raise

# ─── Router connection ────────────────────────────────────────────────────

def connect_to_router(host, port, username, password):
    try:
        connection = routeros_api.RouterOsApiPool(host=host,port=port,username=username,password=password,plaintext_login=True,use_ssl=False)
        api = connection.get_api()
        return api, connection, None
    except Exception as e:
        msg = str(e)
        if 'timed out' in msg.lower(): return None,None,f"Timeout to {host}:{port}"
        elif 'refused' in msg.lower(): return None,None,f"API refused on port {port}"
        elif 'no route' in msg.lower(): return None,None,f"No route to {host}"
        elif 'wrong user' in msg.lower() or 'invalid user' in msg.lower(): return None,None,f"Auth failed for {username}"
        else: return None,None,f"Connection failed: {msg}"

# ─── Field name mapper (RouterOS v6/v7) ──────────────────────────────────

RESOURCE_FIELD_MAP = {
    'cpu-load': 'cpu_load', 'cpu': 'cpu_load',
    'cpu-count': 'cpu_count', 'cpu-core-count': 'cpu_count', 'cpu-core': 'cpu_count',
    'architecture-name': 'architecture_name', 'cpu-architecture': 'architecture_name', 'architecture': 'architecture_name',
    'board-name': 'board_name', 'board': 'board_name', 'hardware': 'board_name',
    'total-memory': 'total_memory', 'memory-size': 'total_memory', 'totalMemory': 'total_memory',
    'free-memory': 'free_memory', 'memory-free': 'free_memory', 'freeMemory': 'free_memory',
    'used-memory': 'used_memory', 'memory-used': 'used_memory', 'usedMemory': 'used_memory',
    'build-time': 'build_time', 'buildTime': 'build_time',
    'factory-software': 'factory_software', 'factorySoftware': 'factory_software',
}

def map_resource_fields(raw):
    """Take a RouterOS resource dict and return a normalized dict with underscored keys"""
    result = {}
    for k, v in raw.items():
        result[k] = v  # keep original
        if k in RESOURCE_FIELD_MAP:
            result[RESOURCE_FIELD_MAP[k]] = v
    # Ensure all expected fields exist
    for field in ['cpu_load','cpu_count','architecture_name','board_name','total_memory','free_memory','used_memory','uptime','version']:
        if field not in result: result[field] = 'N/A'
    return result

# ─── API data retrieval ───────────────────────────────────────────────────

def get_router_info(api):
    """Get simplified router info for dashboard"""
    result = safe_api_call_single(api, '/system/identity')
    router_name = result['data'].get('name', 'N/A') if result['data'] else 'N/A'
    logger.info(f"Identity: {router_name}")
    
    res = safe_api_call_single(api, '/system/resource')
    rd = res['data'] or {}
    logger.info(f"Resource keys: {list(rd.keys())}")
    
    mapped = map_resource_fields(rd)
    
    mem_pct = 'N/A'
    if mapped['total_memory'] != 'N/A' and mapped['used_memory'] != 'N/A' and mapped['total_memory'] != '0':
        try: mem_pct = round((int(mapped['used_memory'])/int(mapped['total_memory'])*100),1)
        except: pass
    
    return {
        'name': router_name,
        'uptime': mapped.get('uptime', 'N/A'),
        'total_memory': mapped['total_memory'],
        'free_memory': mapped['free_memory'],
        'used_memory': mapped['used_memory'],
        'memory_usage_percent': mem_pct,
        'cpu_load': mapped['cpu_load'],
        'cpu_count': mapped['cpu_count'],
        'version': mapped['version'],
        'board_name': mapped['board_name'],
        'architecture_name': mapped['architecture_name'],
    }

def get_detailed_router_info(api):
    """Get full detailed router info for monitor page"""
    details = {}
    api_errors = []
    
    # /system/identity
    r = safe_api_call_single(api, '/system/identity')
    details['identity'] = r['data']
    if r['error']: api_errors.append(f"identity: {r['error']}")
    
    # /system/resource
    r = safe_api_call_single(api, '/system/resource')
    if r['data']:
        details['resources'] = map_resource_fields(r['data'])
    else:
        details['resources'] = {k:'N/A' for k in ['cpu_load','cpu_count','architecture_name','board_name','total_memory','free_memory','used_memory','uptime','version']}
    if r['error']: api_errors.append(f"resource: {r['error']}")
    
    # /system/clock
    r = safe_api_call_single(api, '/system/clock')
    cd = r['data']
    if cd:
        tz = cd.get('time-zone-name', cd.get('time-zone', 'N/A'))
        cd['time_zone_name'] = tz
        details['clock'] = cd
    else:
        details['clock'] = {}
    if r['error']: api_errors.append(f"clock: {r['error']}")
    
    # /ip/address
    r = safe_api_call(api, '/ip/address')
    details['ip_addresses'] = r['data'] if r['data'] else []
    if r['error']: api_errors.append(f"ip/address: {r['error']}")
    
    # /interface
    r = safe_api_call(api, '/interface')
    details['interfaces'] = r['data'] if r['data'] else []
    if r['error']: api_errors.append(f"interface: {r['error']}")
    
    # /ip/dhcp-server/lease
    r = safe_api_call(api, '/ip/dhcp-server/lease')
    details['dhcp_leases'] = r['data'] if r['data'] else []
    if r['error']: api_errors.append(f"dhcp: {r['error']}")
    
    # /ip/arp
    r = safe_api_call(api, '/ip/arp')
    details['arp_table'] = r['data'] if r['data'] else []
    if r['error']: api_errors.append(f"arp: {r['error']}")
    
    # /system/health
    r = safe_api_call_single(api, '/system/health')
    details['health'] = r['data'] if r['data'] else {}
    if r['error']: api_errors.append(f"health: {r['error']}")
    
    # /system/license
    r = safe_api_call_single(api, '/system/license')
    details['license'] = r['data'] if r['data'] else {}
    if r['error']: api_errors.append(f"license: {r['error']}")
    
    # /log
    r = safe_api_call(api, '/log')
    details['logs'] = r['data'] if r['data'] else []
    if r['error']: api_errors.append(f"log: {r['error']}")
    
    if api_errors:
        logger.warning(f"API errors: {'; '.join(api_errors)}")
        details['api_errors'] = api_errors
    
    return details

def get_log_statistics(logs):
    sevs = {'critical':0,'warning':0,'info':0,'error':0,'debug':0,'other':0}
    cats = {}
    for log in logs:
        cat = log.get('topics','other')
        cats[cat] = cats.get(cat,0)+1
        msg = log.get('message','').lower()
        if 'critical' in msg: sevs['critical']+=1
        elif 'warning' in msg: sevs['warning']+=1
        elif 'error' in msg: sevs['error']+=1
        elif 'info' in msg: sevs['info']+=1
        elif 'debug' in msg: sevs['debug']+=1
        else: sevs['other']+=1
    return {'total':len(logs),'categories':dict(sorted(cats.items(),key=lambda x:x[1],reverse=True)),'severities':sevs}

def save_router_logs(router_id, logs):
    conn = sqlite3.connect(db_path); c = conn.cursor(); saved=0
    for log in logs:
        ts=log.get('time',''); topics=log.get('topics',''); msg=log.get('message','')
        ml=msg.lower()
        sev='critical' if 'critical' in ml else 'warning' if 'warning' in ml else 'error' if 'error' in ml else 'info' if 'info' in ml else 'debug' if 'debug' in ml else 'other'
        c.execute('SELECT id FROM router_logs WHERE router_id=? AND timestamp=? AND message=?',(router_id,ts,msg))
        if not c.fetchone():
            c.execute('INSERT INTO router_logs (router_id,timestamp,topics,message,severity) VALUES (?,?,?,?,?)',(router_id,ts,topics,msg,sev)); saved+=1
    conn.commit(); conn.close()
    return saved

def get_log_retention_settings(router_id):
    conn = sqlite3.connect(db_path); c = conn.cursor()
    c.execute('SELECT retention_days FROM log_retention_settings WHERE router_id=?',(router_id,))
    r=c.fetchone(); conn.close(); return r[0] if r else 7

def update_log_retention_settings(router_id, days):
    conn = sqlite3.connect(db_path); c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO log_retention_settings (router_id,retention_days) VALUES (?,?)',(router_id,days))
    conn.commit(); conn.close()

def cleanup_old_logs(router_id):
    import datetime
    days = get_log_retention_settings(router_id)
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    conn = sqlite3.connect(db_path); c = conn.cursor()
    c.execute('DELETE FROM router_logs WHERE router_id=? AND stored_at<?',(router_id,cutoff))
    d=c.rowcount; conn.commit(); conn.close(); return d

def get_paginated_logs(router_id, page=1, per_page=50, severity_filter=None, search_term=None):
    conn = sqlite3.connect(db_path); c = conn.cursor()
    q='SELECT * FROM router_logs WHERE router_id=?'; p=[router_id]
    if severity_filter and severity_filter != 'all': q+=' AND severity=?'; p.append(severity_filter)
    if search_term: q+=' AND (message LIKE ? OR topics LIKE ?)'; p.extend([f'%{search_term}%',f'%{search_term}%'])
    c.execute(q.replace('SELECT *','SELECT COUNT(*)'),p); total=c.fetchone()[0]
    q+=' ORDER BY timestamp DESC LIMIT ? OFFSET ?'; offset=(page-1)*per_page; p.extend([per_page,offset])
    c.execute(q,p); logs=c.fetchall(); conn.close()
    tp=(total+per_page-1)//per_page
    return {'logs':logs,'total_logs':total,'page':page,'per_page':per_page,'total_pages':tp,'has_prev':page>1,'has_next':page<tp}

from contextlib import contextmanager

@contextmanager
def get_db_connection():
    conn=sqlite3.connect(db_path)
    try: yield conn
    finally: conn.close()

def collect_ip_bandwidth_data(router_id, api):
    try:
        traffic_data=[]
        r=safe_api_call(api,'/ip/accounting')
        if r['data']: traffic_data=r['data']
        if not traffic_data:
            r=safe_api_call(api,'/ip/firewall/connection')
            if r['data']:
                for c in r['data']:
                    if c.get('src-address') and c.get('dst-address'):
                        traffic_data.append({'src-address':c['src-address'],'dst-address':c['dst-address'],'bytes':c.get('bytes',0),'packets':c.get('packets',0)})
        arp_table={}
        r=safe_api_call(api,'/ip/arp')
        if r['data']:
            for e in r['data']:
                if e.get('address'): arp_table[e['address']]={'mac_address':e.get('mac-address'),'hostname':e.get('host-name')}
        internal_ips=set()
        r=safe_api_call(api,'/ip/dhcp-server/lease')
        if r['data']:
            for lease in r['data']:
                if lease.get('address'): internal_ips.add(lease['address'])
        r=safe_api_call(api,'/ip/address')
        if r['data']:
            for a in r['data']:
                if a.get('address'): internal_ips.add(a['address'].split('/')[0])
        with get_db_connection() as conn:
            c=conn.cursor(); ip_traffic={}
            for t in traffic_data:
                src=t.get('src-address')
                if src and src in internal_ips:
                    sc=src.split(':')[0] if ':' in src else src
                    if sc not in ip_traffic: ip_traffic[sc]={'rx_bytes':0,'tx_bytes':0}
                    ip_traffic[sc]['tx_bytes']+=int(t.get('bytes',0))
                dst=t.get('dst-address')
                if dst and dst in internal_ips:
                    dc=dst.split(':')[0] if ':' in dst else dst
                    if dc not in ip_traffic: ip_traffic[dc]={'rx_bytes':0,'tx_bytes':0}
                    ip_traffic[dc]['rx_bytes']+=int(t.get('bytes',0))
            batch=[(router_id,ip,arp_table.get(ip,{}).get('mac_address'),arp_table.get(ip,{}).get('hostname'),traffic['rx_bytes'],traffic['tx_bytes']) for ip,traffic in ip_traffic.items()]
            if batch:
                c.executemany('INSERT INTO ip_bandwidth_data (router_id,ip_address,mac_address,hostname,rx_bytes,tx_bytes) VALUES (?,?,?,?,?,?)',batch)
                logger.info(f"Inserted {len(batch)} bandwidth records")
            conn.commit()
        return True
    except Exception as e: logger.error(f"IP bandwidth error: {e}"); return False

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()
def verify_password(p,h): return hash_password(p)==h

def update_router_status_cache(router_id, name, host, port, username, password):
    from datetime import datetime
    import json
    api,connection,error = connect_to_router(host,port,username,password)
    if api:
        info = get_router_info(api)
        connection.disconnect()
        status='online'
        router_info=json.dumps(info)
        source_type='API'
    else:
        status='offline'
        router_info=json.dumps({'error':error or 'Connection failed'})
        source_type='API'
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('INSERT OR REPLACE INTO router_status_cache (router_id,status,last_checked,router_info,source_type,api_port) VALUES (?,?,?,?,?,?)',(router_id,status,datetime.now(),router_info,source_type,port))
    conn.commit(); conn.close()
    return status, router_info

def get_ip_bandwidth_stats(router_id, time_periods):
    import datetime
    stats={}
    conn=sqlite3.connect(db_path); c=conn.cursor()
    periods={'1m':1,'5m':5,'15m':15,'30m':30,'1h':60,'3h':180,'6h':360,'12h':720,'24h':1440,'3d':4320,'1w':10080}
    for name,minutes in periods.items():
        if name in time_periods:
            thr=datetime.datetime.now()-datetime.timedelta(minutes=minutes)
            c.execute('SELECT ip_address,mac_address,hostname,SUM(rx_bytes),SUM(tx_bytes) FROM ip_bandwidth_data WHERE router_id=? AND timestamp>=? GROUP BY ip_address ORDER BY SUM(rx_bytes)+SUM(tx_bytes) DESC',(router_id,thr))
            ps={}
            for row in c.fetchall():
                ps[row[0]]={'mac_address':row[1],'hostname':row[2],'rx_bytes':row[3] or 0,'tx_bytes':row[4] or 0,'rx_mb':(row[3] or 0)/1048576,'tx_mb':(row[4] or 0)/1048576}
            stats[name]=ps
    conn.close()
    return stats

def get_snmp_detailed_info(router_id, host, router_name, router=None):
    info={'identity':{'name':router_name},'resources':{k:'N/A' for k in ['cpu_load','cpu_count','architecture_name','board_name','total_memory','free_memory','used_memory','uptime','version']},'clock':{},'ip_addresses':[],'interfaces':[],'dhcp_leases':[],'arp_table':[],'health':{},'license':{},'logs':[]}
    # Determine ports from router record
    api_port = router[3] if router and len(router) > 3 else 8728
    snmp_port = router[10] if router and len(router) > 10 else 161
    info['_source'] = {'type': 'SNMP', 'api_port': api_port, 'snmp_port': snmp_port, 'port': snmp_port}
    try:
        conn=sqlite3.connect(db_path); c=conn.cursor()
        c.execute('''SELECT cpu_percent,memory_used,memory_total,uptime_seconds,temperature_celsius,cpu_cores,board_name,architecture,platform,firmware,router_name FROM snmp_system_metrics WHERE router_id=? AND cpu_percent IS NOT NULL ORDER BY timestamp DESC LIMIT 1''',(router_id,))
        row=c.fetchone()
        if row and row[0] is not None:
            cpu,mu,mt,up,temp,cpu_cores,board_name,architecture,platform,firmware,router_name = row
            info['resources']={'cpu_load':str(int(cpu)),'total_memory':str(mt) if mt else 'N/A','free_memory':str(mt-mu) if mt and mu else 'N/A','used_memory':str(mu) if mu else 'N/A','uptime':f'{up//3600}h {(up%3600)//60}m' if up else 'N/A','cpu_count':str(cpu_cores) if cpu_cores else 'N/A','version':firmware or 'via SNMP','board_name':board_name or 'N/A','architecture_name':architecture or 'N/A','memory_usage_percent':round((mu/mt)*100,1) if (mt and mu and mt>0) else 'N/A','platform':platform or 'N/A'}
            if temp: info['health']={'temperature':str(temp)}
        c.execute('SELECT DISTINCT interface_name FROM snmp_interface_metrics WHERE router_id=?',(router_id,))
        info['interfaces']=[{'name':r[0],'type':'SNMP','running':'true','mtu':'N/A'} for r in c.fetchall()]
        conn.close()
    except Exception as e: logger.error(f"SNMP info error: {e}")
    return info

BACKUP_DIR=os.path.join(os.path.dirname(db_path) if os.path.dirname(db_path) else '.','backups')
MAX_BACKUPS=30

def ensure_backup_dir(rid):
    d=os.path.join(BACKUP_DIR,str(rid)); os.makedirs(d,exist_ok=True); return d

def run_router_backup(router_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone(); conn.close()
    if not router: return None
    rid,name,host,port,username,password=router[:6]
    api,connection,error=connect_to_router(host,port,username,password)
    if not api: return None
    try:
        r=safe_api_call(api,'/export')
        if r['error'] or not r['data']: return None
        connection.disconnect()
        bd=ensure_backup_dir(router_id)
        fn=datetime.now().strftime('%Y-%m-%d-%H-%M-%S')+'.rsc'
        with open(os.path.join(bd,fn),'w') as f:
            if isinstance(r['data'],list): f.write('\n'.join(str(l) for l in r['data']))
            else: f.write(str(r['data']))
        bl=sorted(glob.glob(os.path.join(bd,'*.rsc')))
        while len(bl)>MAX_BACKUPS: os.remove(bl.pop(0))
        return fn
    except: return None

def get_backup_list(router_id):
    bd=ensure_backup_dir(router_id)
    return [{'filename':os.path.basename(b),'size':os.path.getsize(b),'mtime':datetime.fromtimestamp(os.path.getmtime(b)).strftime('%Y-%m-%d %H:%M:%S')} for b in sorted(glob.glob(os.path.join(bd,'*.rsc')),reverse=True)]

def get_backup_diff(router_id):
    bd=ensure_backup_dir(router_id)
    bl=sorted(glob.glob(os.path.join(bd,'*.rsc')),reverse=True)
    if len(bl)<2: return None,None,"Need 2+ backups"
    f1,f2=bl[0],bl[1]
    try:
        r=subprocess.run(['diff','-u',f2,f1],capture_output=True,text=True,timeout=10)
        return os.path.basename(f1),os.path.basename(f2),r.stdout if r.stdout else "(identical)"
    except:
        with open(f1) as a, open(f2) as b:
            import difflib
            return os.path.basename(f1),os.path.basename(f2),'--- '+os.path.basename(f2)+'\n+++ '+os.path.basename(f1)+'\n'+''.join(difflib.unified_diff(b.readlines(),a.readlines(),n=3))

# ─── Routes ───────────────────────────────────────────────────────────────

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=request.form['username']; p=request.form['password']
        conn=sqlite3.connect(db_path); c=conn.cursor()
        c.execute('SELECT id,username,password_hash,role FROM users WHERE username=?',(u,)); user=c.fetchone(); conn.close()
        if user and verify_password(p,user[2]):
            session['user_id']=user[0]; session['username']=user[1]; session['role']=user[3] if len(user)>3 and user[3] else 'viewer'
            flash('Login successful!','success'); return redirect(url_for('index'))
        else: flash('Invalid credentials','error')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); flash('Logged out','info'); return redirect(url_for('login'))

@app.route('/change_password',methods=['GET','POST'])
@login_required
def change_password():
    if request.method=='POST':
        c=request.form['current_password']; n=request.form['new_password']; cf=request.form['confirm_password']
        if not c or not n or not cf: flash('All fields required','error'); return render_template('change_password.html')
        if n!=cf: flash('Passwords mismatch','error'); return render_template('change_password.html')
        if len(n)<4: flash('Password too short','error'); return render_template('change_password.html')
        conn=sqlite3.connect(db_path); cur=conn.cursor()
        cur.execute('SELECT password_hash FROM users WHERE id=?',(session['user_id'],)); user=cur.fetchone()
        if not user or not verify_password(c,user[0]): flash('Current password wrong','error'); conn.close(); return render_template('change_password.html')
        cur.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(n),session['user_id']))
        conn.commit(); conn.close()
        flash('Password changed!','success'); return redirect(url_for('index'))
    return render_template('change_password.html')

@app.route('/')
@login_required
def index():
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers ORDER BY created_at DESC')
    routers=c.fetchall(); conn.close()
    rdata=[]
    for router in routers:
        rid,name,host,port,username,password=router[:6]
        snmp_enabled=router[7] if len(router)>7 else 0
        # Try cache first
        try:
            c2=sqlite3.connect(db_path); cur=c2.cursor()
            cur.execute('SELECT status,router_info FROM router_status_cache WHERE router_id=? ORDER BY last_checked DESC LIMIT 1',(rid,))
            cache=cur.fetchone(); c2.close()
            if cache and cache[0]=='online' and cache[1]:
                info=json.loads(cache[1])
                source_type = cache[4] if len(cache) > 4 and cache[4] else 'API'
                display_port = cache[5] if len(cache) > 5 and cache[5] and source_type == 'SNMP' else (cache[6] if len(cache) > 6 and cache[6] else port)
                rdata.append({'id':rid,'name':name,'host':host,'port':port,'display_port':display_port,'info':info,'status':'online','cached':True,'source_type':source_type})
                continue
        except: pass
        
        if snmp_enabled:
            si=get_snmp_detailed_info(rid,host,name,router)
            res=si.get('resources',{})
            src_info = si.get('_source', {})
            display_snmp_port = src_info.get('port', 161)
            if res.get('cpu_load') and res['cpu_load']!='N/A':
                rdata.append({'id':rid,'name':name,'host':host,'port':port,'display_port':display_snmp_port,'info':{'name':name,'uptime':res.get('uptime','via SNMP'),'memory_usage_percent':res.get('memory_usage_percent','N/A'),'used_memory':res.get('used_memory','N/A'),'total_memory':res.get('total_memory','N/A'),'cpu_load':res.get('cpu_load','N/A'),'cpu_count':res.get('cpu_count','N/A'),'version':res.get('version','via SNMP'),'board_name':res.get('board_name','N/A'),'architecture_name':res.get('architecture_name','N/A')},'status':'online','source_type':'SNMP'})
            else:
                rdata.append({'id':rid,'name':name,'host':host,'port':port,'display_port':display_snmp_port,'info':{'name':name,'uptime':'collecting...','memory_usage_percent':'N/A','used_memory':'N/A','total_memory':'N/A','cpu_load':'N/A','cpu_count':'N/A','cpu_frequency':'N/A','version':'N/A','board_name':'N/A','architecture_name':'N/A'},'status':'online','source_type':'SNMP'})
        elif username and password:
            api,conn_err,err=connect_to_router(host,port,username,password)
            if api:
                info=get_router_info(api); conn_err.disconnect()
                # Update cache
                try:
                    c3=sqlite3.connect(db_path); cu=c3.cursor()
                    cu.execute('INSERT OR REPLACE INTO router_status_cache (router_id,status,last_checked,router_info,source_type,api_port) VALUES (?,?,?,?,?,?)',(rid,'online',datetime.now(),json.dumps(info),'API',port))
                    c3.commit(); c3.close()
                except: pass
                rdata.append({'id':rid,'name':name,'host':host,'port':port,'display_port':port,'info':info,'status':'online','source_type':'API'})
            else:
                rdata.append({'id':rid,'name':name,'host':host,'port':port,'display_port':port,'info':{'error':err or 'Connection failed'},'status':'offline','source_type':'API'})
        else:
            rdata.append({'id':rid,'name':name,'host':host,'port':port,'display_port':port,'info':{'error':'No connection method'},'status':'offline','source_type':'N/A'})
    return render_template('index.html',routers=rdata,session=session)

@app.route('/add_router',methods=['GET','POST'])
@login_required
@role_required('operator')
def add_router():
    if request.method=='POST':
        name=request.form['name']; host=request.form['host']
        api_enabled=request.form.get('api_enabled',0,type=int)
        snmp_enabled=request.form.get('snmp_enabled',0,type=int)
        errors=[]
        api_conn=None; api_connection=None
        if api_enabled:
            port=request.form.get('port',8728,type=int); username=request.form.get('username',''); password=request.form.get('password','')
            api_conn,api_connection,error=connect_to_router(host,port,username,password)
            if not api_conn: errors.append(f"API: {error}")
        else: port=8728; username=''; password=''
        if snmp_enabled:
            sc=request.form.get('snmp_community','public'); sv=request.form.get('snmp_version',2,type=int); sp=request.form.get('snmp_port',161,type=int)
            su=request.form.get('snmp_user',''); sap=request.form.get('snmp_auth_protocol','MD5'); sapw=request.form.get('snmp_auth_pass',''); spp=request.form.get('snmp_priv_protocol','DES'); sppw=request.form.get('snmp_priv_pass','')
            if sv==2:
                if not test_snmp_connection(host,sc,2,sp): errors.append(f"SNMP: Connection failed to {host}:{sp}")
            else: errors.append("SNMP v3 not supported")
        else: sc='public'; sv=2; sp=161; su=''; sap='MD5'; sapw=''; spp='DES'; sppw=''
        if errors:
            for e in errors: flash(e,'error')
            return render_template('add_router.html',r={'name':name,'host':host,'port':port,'username':username,'api_enabled':api_enabled,'snmp_enabled':snmp_enabled,'snmp_community':sc,'snmp_version':sv,'snmp_port':sp,'snmp_user':su,'snmp_auth_protocol':sap,'snmp_auth_pass':sapw,'snmp_priv_protocol':spp,'snmp_priv_pass':sppw})
        conn=sqlite3.connect(db_path); c=conn.cursor()
        c.execute('''INSERT INTO routers (name,host,port,username,password,snmp_enabled,snmp_community,snmp_version,snmp_port,snmp_user,snmp_auth_protocol,snmp_auth_pass,snmp_priv_protocol,snmp_priv_pass) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(name,host,port,username,password,snmp_enabled,sc,sv,sp,su,sap,sapw,spp,sppw))
        conn.commit(); conn.close()
        if api_connection: api_connection.disconnect()
        flash('Router added!','success'); return redirect(url_for('index'))
    return render_template('add_router.html')

@app.route('/edit_router/<int:router_id>',methods=['GET','POST'])
@login_required
@role_required('operator')
def edit_router(router_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone()
    if not router: conn.close(); flash('Not found','error'); return redirect(url_for('index'))
    if request.method=='POST':
        name=request.form['name']; host=request.form['host']
        api_enabled=request.form.get('api_enabled',0,type=int); snmp_enabled=request.form.get('snmp_enabled',0,type=int)
        errors=[]; api_conn=None; api_connection=None
        if api_enabled:
            api_port=request.form.get('port',8728,type=int); username=request.form.get('username',''); npw=request.form.get('password','')
            tp=npw if npw else router[5]
            api_conn,api_connection,err=connect_to_router(host,api_port,username,tp)
            if not api_conn: errors.append(f"API: {err}")
        else: api_port=router[3]; username=router[4]; npw=''
        if snmp_enabled:
            sc=request.form.get('snmp_community','public'); sv=request.form.get('snmp_version',2,type=int); sp=request.form.get('snmp_port',161,type=int)
            su=request.form.get('snmp_user',''); sap=request.form.get('snmp_auth_protocol','MD5'); sapw=request.form.get('snmp_auth_pass',''); spp=request.form.get('snmp_priv_protocol','DES'); sppw=request.form.get('snmp_priv_pass','')
            if sv==2:
                if not test_snmp_connection(host,sc,2,sp): errors.append(f"SNMP: Failed to {host}:{sp}")
            else: errors.append("SNMP v3 unsupported")
        else:
            sc=router[8] if len(router)>8 else 'public'; sv=router[9] if len(router)>9 else 2; sp=router[10] if len(router)>10 else 161
            su=router[11] if len(router)>11 else ''; sap=router[12] if len(router)>12 else 'MD5'; sapw=router[13] if len(router)>13 else ''; spp=router[14] if len(router)>14 else 'DES'; sppw=router[15] if len(router)>15 else ''
        if errors:
            conn.close()
            for e in errors: flash(e,'error')
            return render_template('add_router.html',edit_mode=True,r={'name':name,'host':host,'port':api_port if api_enabled else router[3],'username':username if api_enabled else router[4],'api_enabled':api_enabled,'snmp_enabled':snmp_enabled,'snmp_community':sc,'snmp_version':sv,'snmp_port':sp,'snmp_user':su,'snmp_auth_protocol':sap,'snmp_auth_pass':sapw,'snmp_priv_protocol':spp,'snmp_priv_pass':sppw})
        fp=npw if npw else router[5]
        if not api_enabled: fp=router[5]; username=router[4]; api_port=router[3]
        c.execute('''UPDATE routers SET name=?,host=?,port=?,username=?,password=?,snmp_enabled=?,snmp_community=?,snmp_version=?,snmp_port=?,snmp_user=?,snmp_auth_protocol=?,snmp_auth_pass=?,snmp_priv_protocol=?,snmp_priv_pass=? WHERE id=?''',(name,host,api_port,username,fp,snmp_enabled,sc,sv,sp,su,sap,sapw,spp,sppw,router_id))
        conn.commit(); conn.close()
        if api_connection: api_connection.disconnect()
        flash('Router updated!','success'); return redirect(url_for('index'))
    conn.close()
    return render_template('add_router.html',edit_mode=True,r={'name':router[1],'host':router[2],'port':router[3],'username':router[4],'api_enabled':1,'snmp_enabled':router[7] if len(router)>7 else 0,'snmp_community':router[9] if len(router)>9 else 'public','snmp_version':router[10] if len(router)>10 else 2,'snmp_port':router[11] if len(router)>11 else 161,'snmp_user':router[12] if len(router)>12 else '','snmp_auth_protocol':router[13] if len(router)>13 else 'MD5','snmp_auth_pass':router[14] if len(router)>14 else '','snmp_priv_protocol':router[15] if len(router)>15 else 'DES','snmp_priv_pass':router[16] if len(router)>16 else ''})

@app.route('/delete_router/<int:router_id>')
@login_required
@role_required('admin')
def delete_router(router_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('DELETE FROM routers WHERE id=?',(router_id,)); conn.commit(); conn.close()
    flash('Router deleted!','success'); return redirect(url_for('index'))

@app.route('/refresh_router/<int:router_id>')
@login_required
@role_required('operator')
def refresh_router(router_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone(); conn.close()
    if router:
        rid,name,host,port,username,password=router[:6]
        status,ri=update_router_status_cache(rid,name,host,port,username,password)
        flash('Refreshed!' if status=='online' else 'Failed to connect','success' if status=='online' else 'error')
    return redirect(url_for('index'))

@app.route('/monitor_router/<int:router_id>')
@login_required
def monitor_router(router_id):
    period=request.args.get('period','1h')
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone(); conn.close()
    if not router: flash('Not found','error'); return redirect(url_for('index'))
    snmp_enabled=router[7] if len(router)>7 else 0
    rd={'id':router[0],'name':router[1],'host':router[2],'port':router[3],'snmp_enabled':snmp_enabled}
    rid,name,host,port,username,password=router[:6]
    now=datetime.now()
    tps=[('1m','1 min'),('5m','5 min'),('15m','15 min'),('30m','30 min'),('1h','1 hour'),('3h','3 hours'),('6h','6 hours'),('12h','12 hours'),('24h','24 hours'),('3d','3 days'),('1w','1 week')]
    alerts=[]
    try:
        c2=sqlite3.connect(db_path); cu=c2.cursor()
        cu.execute('''SELECT ae.id,ae.status,ae.message,ae.triggered_at,ar.metric_type,ar.condition,ar.threshold_value FROM alert_events ae JOIN alert_rules ar ON ae.rule_id=ar.id WHERE ae.router_id=? ORDER BY ae.triggered_at DESC LIMIT 50''',(rid,))
        alerts=[{'id':r[0],'status':r[1],'message':r[2],'triggered_at':r[3],'metric_type':r[4],'condition':r[5],'threshold':r[6]} for r in cu.fetchall()]
        c2.close()
    except: pass
    if snmp_enabled:
        si=get_snmp_detailed_info(rid,host,name,router)
        has_snmp_data = si['resources'].get('cpu_load') and si['resources']['cpu_load'] != 'N/A'
        if has_snmp_data:
            src_info = si.get('_source', {})
            return render_template('monitor.html',router=rd,info=si,bandwidth_stats={},log_stats={'total':0,'categories':{},'severities':{}},selected_period=period,time_periods=tps,alerts=alerts,backups=[],now=now,connection_mode='snmp',source_type='SNMP',source_port=src_info.get('port', 161),source_label='SNMP')
        # SNMP enabled but no data yet — fall through to API if available
        logger.info(f"SNMP has no data for router {rid}, falling back to API")
    if snmp_enabled and (not username or not password):
        return render_template('monitor.html',router=rd,info=si,bandwidth_stats={},log_stats={'total':0,'categories':{},'severities':{}},selected_period=period,time_periods=tps,alerts=alerts,backups=[],now=now,connection_mode='snmp',source_type='SNMP',source_port=snmp_port if 'snmp_port' in dir() else 161,source_label='SNMP')
    if not username or not password:
        return render_template('error.html',error='No connection method configured'),200
    api,conn_err,api_err=connect_to_router(host,port,username,password)
    if not api: return render_template('error.html',error=api_err),200
    detailed_info=get_detailed_router_info(api)
    log_stats=get_log_statistics(detailed_info.get('logs',[]))
    conn_err.disconnect()
    bw=get_ip_bandwidth_stats(rid,[period])
    backups=get_backup_list(rid)
    return render_template('monitor.html',router=rd,info=detailed_info,bandwidth_stats=bw,log_stats=log_stats,selected_period=period,time_periods=tps,alerts=alerts,backups=backups,now=now,connection_mode='api',source_type='API',source_port=port,source_label='API')

@app.route('/api/monitor/<int:router_id>')
@login_required
def api_monitor_router(router_id):
    period=request.args.get('period','1h')
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone(); conn.close()
    if not router: return jsonify({'success':False,'error':'Router not found'}),404
    rid,name,host,port,username,password=router[:6]
    api,connection,error=connect_to_router(host,port,username,password)
    if not api: return jsonify({'success':False,'error':error}),500
    try:
        errors={}
        si=get_router_info(api)
        if 'error' in si: errors['system_info']=si['error']
        di=get_detailed_router_info(api)
        if di.get('api_errors'): errors['api_errors']=di['api_errors']
        bw=get_ip_bandwidth_stats(rid,[period])
        connection.disconnect()
        result={'success':True,'data':{'system_info':si,'tables':{'ip_addresses':di.get('ip_addresses',[]),'dhcp_leases':di.get('dhcp_leases',[]),'arp_table':di.get('arp_table',[]),'interfaces':di.get('interfaces',[]),'resources':di.get('resources',{}),'clock':di.get('clock',{}),'health':di.get('health',{}),'license':di.get('license',{})},'bandwidth_stats':bw}}
        if errors: result['warnings']=errors
        return jsonify(result)
    except Exception as e:
        if connection: connection.disconnect()
        logger.error(f"api_monitor error: {e}\n{traceback.format_exc()}")
        return jsonify({'success':False,'error':str(e)}),500

@app.route('/api/debug/<int:router_id>')
@login_required
def api_debug(router_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone(); conn.close()
    if not router: return jsonify({'success':False,'error':'Not found'}),404
    rid,name,host,port,username,password=router[:6]
    api,connection,error=connect_to_router(host,port,username,password)
    if not api: return jsonify({'success':False,'error':error}),500
    debug={}
    for path in ['/system/resource','/system/identity','/interface','/ip/address','/ip/dhcp-server/lease','/ip/arp','/system/clock','/system/health','/system/license','/log']:
        try:
            r=api.get_resource(path); d=r.get() if r.get() else []
            debug[path]=d[:5] if len(d)>5 else d
        except Exception as e: debug[path]=f"ERROR: {e}"
    connection.disconnect()
    return jsonify({'success':True,'data':debug})

def get_ip_bandwidth_history(router_id, ip_address, time_period):
    import datetime
    periods={'1h':60,'3h':180,'6h':360,'12h':720,'24h':1440,'3d':4320,'1w':10080}
    if time_period not in periods: return {'error':'Invalid period'}
    thr=(datetime.datetime.now()-datetime.timedelta(minutes=periods[time_period])).strftime('%Y-%m-%d %H:%M:%S')
    conn=sqlite3.connect(db_path); c=conn.cursor()
    try:
        c.execute('SELECT timestamp,rx_bytes,tx_bytes FROM ip_bandwidth_data WHERE router_id=? AND ip_address=? AND timestamp>=? ORDER BY timestamp',(router_id,ip_address,thr))
        rows=c.fetchall(); dps=[]
        for i,row in enumerate(rows):
            ts,rx,tx=row
            if i==0: d,u=0,0
            else:
                prev=datetime.datetime.strptime(rows[i-1][0],'%Y-%m-%d %H:%M:%S')
                cur=datetime.datetime.strptime(ts,'%Y-%m-%d %H:%M:%S')
                diff=(cur-prev).total_seconds()
                if diff>0: d=((rx or 0)*8)/diff/1000000; u=((tx or 0)*8)/diff/1000000
                else: d,u=0,0
            dps.append({'timestamp':ts,'download_mbps':d,'upload_mbps':u,'total_mbps':d+u})
        conn.close(); return dps
    except Exception as e: conn.close(); raise

def get_router_connections(router_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone(); conn.close()
    if not router: return {'error':'Not found'}
    rid,name,host,port,username,password=router[:6]
    api,connection,error=connect_to_router(host,port,username,password)
    if not api: return {'error':error or 'Failed to connect'}
    try:
        ip_data=safe_api_call(api,'/ip/address')['data'] or []
        leases_data=safe_api_call(api,'/ip/dhcp-server/lease')['data'] or []
        arp_data=safe_api_call(api,'/ip/arp')['data'] or []
        routes_data=safe_api_call(api,'/ip/route')['data'] or []
        ifaces_data=safe_api_call(api,'/interface')['data'] or []
        result=[]
        for ip_addr in ip_data:
            address=ip_addr.get('address',''); interface=ip_addr.get('interface','')
            if not address or not interface: continue
            ip=address.split('/')[0]
            if ip.startswith('127.') or ip.startswith('169.254.'): continue
            clients=[]
            for lease in leases_data:
                if lease.get('address') and lease.get('server')==ip:
                    ai=None
                    for a in arp_data:
                        if a.get('address')==lease['address']: ai=a; break
                    clients.append({'ip':lease['address'],'mac':lease.get('mac-address',''),'hostname':lease.get('host-name',''),'status':lease.get('status','unknown'),'interface':ai.get('interface','') if ai else '','dynamic':ai.get('dynamic',False) if ai else False})
            upstream=None
            for route in routes_data:
                if route.get('dst-address')=='0.0.0.0/0' and route.get('interface')==interface:
                    upstream={'gateway':route.get('gateway',''),'interface':route.get('interface',''),'type':'default_route'}; break
            if not upstream:
                for iface in ifaces_data:
                    if iface.get('name')==interface and iface.get('master-port'):
                        upstream={'gateway':'N/A','interface':iface['master-port'],'type':'bridge_parent'}; break
            if not upstream: upstream={'gateway':'Direct to WAN','interface':interface,'type':'direct'}
            result.append({'ip':ip,'interface':interface,'network':address,'clients':clients,'client_count':len(clients),'upstream':upstream})
        connection.disconnect(); return result
    except Exception as e:
        if connection: connection.disconnect(); logger.error(f"Connections error: {e}"); return {'error':str(e)}

def get_interface_bandwidth_data(router_id, time_period):
    import datetime
    periods={'1h':60,'3h':180,'6h':360,'12h':720,'24h':1440,'3d':4320,'1w':10080}
    if time_period not in periods: return {'error':'Invalid period'}
    thr=(datetime.datetime.now()-datetime.timedelta(minutes=periods[time_period])).strftime('%Y-%m-%d %H:%M:%S')
    conn=sqlite3.connect(db_path); c=conn.cursor()
    try:
        c.execute('SELECT interface_name,timestamp,rx_bytes,tx_bytes FROM interface_bandwidth_data WHERE router_id=? AND timestamp>=? ORDER BY interface_name,timestamp',(router_id,thr))
        rows=c.fetchall(); groups={}
        for r in rows: groups.setdefault(r[0],[]).append((r[1],r[2],r[3]))
        result={}
        for iface,pts in groups.items():
            data=[]
            for i,(ts,rx,tx) in enumerate(pts):
                if i==0: d,u=0,0
                else:
                    prev=datetime.datetime.strptime(pts[i-1][0],'%Y-%m-%d %H:%M:%S')
                    cur=datetime.datetime.strptime(ts,'%Y-%m-%d %H:%M:%S')
                    diff=(cur-prev).total_seconds()
                    if diff>0: d=((rx or 0)*8)/diff/1000000; u=((tx or 0)*8)/diff/1000000
                    else: d,u=0,0
                data.append({'timestamp':ts,'download_mbps':d,'upload_mbps':u,'total_mbps':d+u})
            result[iface]=data
        conn.close(); return result
    except: conn.close(); return {}

@app.route('/backup/<int:router_id>')
@login_required
@role_required('operator')
def trigger_backup(router_id):
    result=run_router_backup(router_id)
    flash(f'Backup saved: {result}' if result else 'Backup failed','success' if result else 'error')
    return redirect(url_for('monitor_router',router_id=router_id))

@app.route('/backup_diff/<int:router_id>')
@login_required
def backup_diff(router_id):
    newer,older,dt=get_backup_diff(router_id)
    if dt is None: flash('Need 2+ backups','error'); return redirect(url_for('monitor_router',router_id=router_id))
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT name FROM routers WHERE id=?',(router_id,)); r=c.fetchone(); conn.close()
    return render_template('backup_diff.html',router={'id':router_id,'name':r[0] if r else 'Unknown'},newer=newer,older=older,diff_text=dt)

@app.route('/api/alerts/<int:router_id>')
@login_required
def api_alerts(router_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('''SELECT ae.id,ae.status,ae.message,ae.triggered_at,ar.metric_type FROM alert_events ae JOIN alert_rules ar ON ae.rule_id=ar.id WHERE ae.router_id=? ORDER BY ae.triggered_at DESC LIMIT 100''',(router_id,))
    al=[{'id':r[0],'status':r[1],'message':r[2],'triggered_at':r[3],'metric_type':r[4]} for r in c.fetchall()]
    conn.close()
    return jsonify({'success':True,'data':al})

@app.route('/api/alerts/acknowledge/<int:alert_id>',methods=['POST'])
@login_required
@role_required('operator')
def api_acknowledge_alert(alert_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute("UPDATE alert_events SET status='acknowledged' WHERE id=?",(alert_id,))
    conn.commit(); conn.close()
    return jsonify({'success':True})

@app.route('/api/alert_rules/<int:router_id>',methods=['GET','POST'])
@login_required
@role_required('operator')
def api_alert_rules(router_id):
    if request.method=='POST':
        data=request.get_json()
        conn=sqlite3.connect(db_path); c=conn.cursor()
        c.execute('''INSERT INTO alert_rules (router_id,metric_type,condition,threshold_value,duration_seconds,action,action_config) VALUES (?,?,?,?,?,?,?)''',(router_id,data['metric_type'],data['condition'],data['threshold_value'],data.get('duration_seconds',0),data['action'],json.dumps(data.get('action_config',{}))))
        conn.commit(); rid=c.lastrowid; conn.close()
        return jsonify({'success':True,'rule_id':rid})
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM alert_rules WHERE router_id=? ORDER BY created_at DESC',(router_id,))
    rules=[{'id':r[0],'router_id':r[1],'metric_type':r[2],'condition':r[3],'threshold_value':r[4],'duration_seconds':r[5],'action':r[6],'action_config':r[7],'enabled':r[8],'created_at':r[9]} for r in c.fetchall()]
    conn.close()
    return jsonify({'success':True,'data':rules})

@app.route('/api/alert_rules/<int:rule_id>/delete',methods=['POST'])
@login_required
@role_required('admin')
def api_delete_alert_rule(rule_id):
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('DELETE FROM alert_rules WHERE id=?',(rule_id,)); c.execute('DELETE FROM alert_events WHERE rule_id=?',(rule_id,))
    conn.commit(); conn.close()
    return jsonify({'success':True})

@app.route('/update_log_retention/<int:router_id>',methods=['POST'])
@login_required
@role_required('admin')
def update_log_retention(router_id):
    days=request.form.get('retention_days',7,type=int)
    if days not in [1,3,7,30,90]: flash('Invalid','error'); return redirect(url_for('router_logs',router_id=router_id))
    update_log_retention_settings(router_id,days); cleanup_old_logs(router_id)
    flash(f'Retention set to {days} days','success')
    return redirect(url_for('router_logs',router_id=router_id))

@app.route('/export_logs_csv/<int:router_id>')
@login_required
def export_logs_csv(router_id):
    import csv,io
    sev=request.args.get('severity','all'); search=request.args.get('search','')
    conn=sqlite3.connect(db_path); c=conn.cursor()
    q='SELECT timestamp,topics,message,severity,stored_at FROM router_logs WHERE router_id=?'; p=[router_id]
    if sev!='all': q+=' AND severity=?'; p.append(sev)
    if search: q+=' AND (message LIKE ? OR topics LIKE ?)'; p.extend([f'%{search}%',f'%{search}%'])
    q+=' ORDER BY timestamp DESC'
    c.execute(q,p); logs=c.fetchall()
    c.execute('SELECT name FROM routers WHERE id=?',(router_id,)); rname=c.fetchone()[0]; conn.close()
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(['Timestamp','Category','Message','Severity','Stored At','Router Name'])
    for l in logs: w.writerow(list(l)+[rname])
    out.seek(0)
    ts=datetime.now().strftime('%Y%m%d_%H%M%S')
    return app.response_class(response=out.getvalue(),status=200,mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename={rname}_logs_{ts}.csv'})

@app.route('/api/chart/bandwidth/<int:router_id>')
@login_required
def api_chart_bandwidth(router_id):
    ip=request.args.get('ip'); period=request.args.get('period','1h')
    if not ip: return jsonify({'success':False,'error':'IP required'}),400
    try: return jsonify({'success':True,'data':get_ip_bandwidth_history(router_id,ip,period),'ip_address':ip,'time_period':period})
    except Exception as e: return jsonify({'success':False,'error':str(e)}),500

@app.route('/api/chart/interface_bandwidth/<int:router_id>')
@login_required
def api_chart_interface_bandwidth(router_id):
    iface=request.args.get('interface'); period=request.args.get('period','1h')
    if not iface: return jsonify({'success':False,'error':'Interface required'}),400
    try:
        data=get_interface_bandwidth_data(router_id,period)
        return jsonify({'success':True,'data':data.get(iface,[]),'interface_name':iface,'time_period':period})
    except Exception as e: return jsonify({'success':False,'error':str(e)}),500

@app.route('/api/network-connections/<int:router_id>')
@login_required
def api_router_network_connections(router_id):
    try:
        data=get_router_connections(router_id)
        if 'error' in data: return jsonify({'success':False,'error':data['error']}),500
        return jsonify({'success':True,'data':data,'timestamp':datetime.now().isoformat()})
    except Exception as e: return jsonify({'success':False,'error':str(e)}),500

@app.route('/connections/<int:router_id>')
@login_required
def connections_page(router_id):
    page=request.args.get('page',1,type=int); sort=request.args.get('sort','download_desc')
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone(); conn.close()
    if not router: flash('Not found','error'); return redirect(url_for('index'))
    rid,name,host,port=router[:4]
    cd=get_live_firewall_connections(rid)
    if 'error' not in cd:
        conns=cd['connections']
        if sort=='download_desc': conns.sort(key=lambda x:x['download_bytes'],reverse=True)
        elif sort=='upload_desc': conns.sort(key=lambda x:x['upload_bytes'],reverse=True)
        elif sort=='duration_desc': conns.sort(key=lambda x:x.get('duration',''),reverse=True)
        elif sort=='src_ip_asc': conns.sort(key=lambda x:x['src_ip'])
        pp=20; total=len(conns); tp=max(1,(total+pp-1)//pp); page=max(1,min(page,tp)); start=(page-1)*pp
        cd['connections']=conns[start:start+pp]; cd['pagination']={'page':page,'per_page':pp,'total_connections':total,'total_pages':tp,'has_prev':page>1,'has_next':page<tp,'sort_by':sort}
    return render_template('connections.html',router={'id':rid,'name':name,'host':host,'port':port},connections_data=cd)

@app.route('/api/connections/<int:router_id>')
@login_required
def api_connections(router_id):
    try:
        data=get_live_firewall_connections(router_id)
        if 'error' in data: return jsonify({'success':False,'error':data['error']}),500
        return jsonify({'success':True,'data':data,'timestamp':datetime.now().isoformat()})
    except Exception as e: return jsonify({'success':False,'error':str(e)}),500

@app.route('/api/connection-count/<int:router_id>')
@login_required
def api_connection_count(router_id):
    try:
        data=get_live_firewall_connections(router_id)
        if 'error' in data: return jsonify({'success':False,'error':data['error']}),500
        return jsonify({'success':True,'count':data.get('total_count',0)})
    except Exception as e: return jsonify({'success':False,'error':str(e)}),500

@app.route('/router_logs/<int:router_id>')
@login_required
def router_logs(router_id):
    page=request.args.get('page',1,type=int); sev=request.args.get('severity','all'); search=request.args.get('search','')
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone()
    if not router: conn.close(); flash('Not found','error'); return redirect(url_for('index'))
    rid,name,host,port,username,password=router[:6]
    api,conn_err,error=connect_to_router(host,port,username,password)
    if api:
        try:
            logs=api.get_resource('/log').get() or []
            logger.info(f"Fetched {len(logs)} logs")
            saved=save_router_logs(rid,logs); cleanup_old_logs(rid)
            conn_err.disconnect()
            if saved>0: flash(f'Updated {saved} logs','success')
        except Exception as e:
            if conn_err: conn_err.disconnect()
            logger.error(f"Log fetch: {e}")
    conn.close()
    pag=get_paginated_logs(rid,page,50,sev,search)
    conn2=sqlite3.connect(db_path); cur=conn2.cursor()
    cur.execute('SELECT COUNT(*) FROM router_logs WHERE router_id=?',(rid,)); total=cur.fetchone()[0]
    cur.execute('SELECT severity,COUNT(*) FROM router_logs WHERE router_id=? GROUP BY severity',(rid,))
    sevs={r[0]:r[1] for r in cur.fetchall()}
    cur.execute('SELECT topics,COUNT(*) FROM router_logs WHERE router_id=? GROUP BY topics',(rid,))
    cats={r[0]:r[1] for r in cur.fetchall()}
    conn2.close()
    ret=get_log_retention_settings(rid)
    return render_template('router_logs.html',router={'id':rid,'name':name,'host':host,'port':port},logs=pag['logs'],log_stats={'total':total,'severities':sevs,'categories':cats},pagination=pag,retention_days=ret,current_severity=sev,current_search=search)

def get_live_firewall_connections(router_id):
    ct=time.time()
    with firewall_cache_lock:
        if router_id in firewall_connections_cache:
            cached,ts=firewall_connections_cache[router_id]
            if ct-ts<10: return cached
    conn=sqlite3.connect(db_path); c=conn.cursor()
    c.execute('SELECT * FROM routers WHERE id=?',(router_id,)); router=c.fetchone(); conn.close()
    if not router: return {'error':'Not found'}
    rid,name,host,port,username,password=router[:6]
    api,connection,error=connect_to_router(host,port,username,password)
    if not api: return {'error':error or 'Failed to connect'}
    try:
        r=safe_api_call(api,'/ip/firewall/connection')
        connections_data=r['data'] if r['data'] else []
        logger.info(f"Firewall connections: {len(connections_data)} items")
        hostname_map={}
        r2=safe_api_call(api,'/ip/dhcp-server/lease')
        if r2['data']:
            for lease in r2['data']:
                if lease.get('address') and lease.get('host-name'): hostname_map[lease['address']]=lease['host-name']
        r3=safe_api_call(api,'/ip/arp')
        if r3['data']:
            for arp in r3['data']:
                if arp.get('address') and arp.get('host-name') and arp['address'] not in hostname_map: hostname_map[arp['address']]=arp['host-name']
        processed=[]; total_count=0; total_up=0; total_down=0
        for cxn in connections_data:
            src=cxn.get('src-address','').split(':')[0]; dst=cxn.get('dst-address','').split(':')[0]; proto=cxn.get('protocol','')
            if not src or not dst: continue
            internal_nets=('192.168.','10.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.','172.31.')
            is_internal=any(src.startswith(n) for n in internal_nets)
            is_external=not dst.startswith(('192.168.','10.','172.'))
            if is_internal and is_external:
                total_count+=1
                bf=cxn.get('bytes','0/0')
                sent,recv=map(int,bf.split('/')) if '/' in bf else (0,0)
                up=sent; down=recv; total_up+=up; total_down+=down
                dport=cxn.get('dst-port','0'); uptime=cxn.get('orig-time','0s')
                dur=parse_routeros_duration(uptime); svc=get_service_name_simple(dport,proto)
                sni=cxn.get('sni','')
                processed.append({'src_ip':src,'src_hostname':hostname_map.get(src,'-'),'dst_ip':dst,'dst_hostname':sni or dst,'service':svc,'upload_bytes':up,'download_bytes':down,'upload_human':format_bytes(up),'download_human':format_bytes(down),'duration':dur,'protocol':proto,'total_bytes':up+down})
        processed.sort(key=lambda x:x['total_bytes'],reverse=True)
        connection.disconnect()
        result={'connections':processed,'total_count':total_count,'total_upload':total_up,'total_download':total_down,'total_upload_human':format_bytes(total_up),'total_download_human':format_bytes(total_down),'timestamp':ct}
        with firewall_cache_lock: firewall_connections_cache[router_id]=(result,ct)
        return result
    except Exception as e:
        if connection: connection.disconnect()
        logger.error(f"Firewall error: {e}\n{traceback.format_exc()}")
        return {'error':str(e),'connections':[],'total_count':0,'total_upload':0,'total_download':0,'total_upload_human':'0 B','total_download_human':'0 B'}

def parse_routeros_duration(ds):
    if not ds or ds=='0s': return '0s'
    h=m=s=0
    hm=re.search(r'(\d+)h',ds)
    if hm: h=int(hm.group(1))
    mm=re.search(r'(\d+)m',ds)
    if mm: m=int(mm.group(1))
    sm=re.search(r'(\d+)s',ds)
    if sm: s=int(sm.group(1))
    if h>0: return f"{h}h {m}m {s}s"
    elif m>0: return f"{m}m {s}s"
    else: return f"{s}s"

def get_service_name_simple(dport, proto):
    ports={'80':'HTTP','443':'HTTPS','53':'DNS','853':'DNS-over-TLS','22':'SSH','21':'FTP','25':'SMTP','110':'POP3','143':'IMAP','993':'IMAPS','995':'POP3S','587':'SMTP','465':'SMTPS','1194':'OpenVPN','1723':'PPTP','3389':'RDP','5900':'VNC','8080':'HTTP','8443':'HTTPS','123':'NTP','161':'SNMP','162':'SNMP','514':'Syslog','5060':'SIP','5061':'SIPS'}
    return ports.get(dport,f'{proto.upper()}/{dport}')

if __name__=='__main__':
    init_db()
    logger.info(f"Starting on port 8080, DB: {db_path}")
    app.run(host='0.0.0.0',port=8080,debug=True)
