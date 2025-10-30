from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime
import routeros_api
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Global database path
db_path = 'data/routers.db'

# Database setup
def init_db():
    global db_path
    import os
    
    # Use persistent data directory
    data_dir = 'data'
    os.makedirs(data_dir, exist_ok=True)
    # db_path is already set globally
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Create routers table
        c.execute('''
            CREATE TABLE IF NOT EXISTS routers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 8728,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create per-IP bandwidth monitoring table
        c.execute('''
            CREATE TABLE IF NOT EXISTS ip_bandwidth_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                rx_bytes INTEGER DEFAULT 0,
                tx_bytes INTEGER DEFAULT 0,
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create router status cache table
        c.execute('''
            CREATE TABLE IF NOT EXISTS router_status_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                info_json TEXT,
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create index for faster queries
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_router_time ON ip_bandwidth_data (router_id, timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_ip ON ip_bandwidth_data (ip_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_mac ON ip_bandwidth_data (mac_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_router_status_time ON router_status_cache (last_checked)')
        
        conn.commit()
        conn.close()
        print(f"Database initialized successfully at {db_path}")
        # Continue to ensure all tables are created
    except Exception as e:
        print(f"Error initializing database at {db_path}: {e}")
    
    # Try current directory as fallback
    fallback_db_path = 'routers.db'
    try:
        conn = sqlite3.connect(fallback_db_path)
        c = conn.cursor()
        
        # Create all tables in fallback database
        c.execute('''
            CREATE TABLE IF NOT EXISTS routers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 8728,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create per-IP bandwidth monitoring table
        c.execute('''
            CREATE TABLE IF NOT EXISTS ip_bandwidth_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                rx_bytes INTEGER DEFAULT 0,
                tx_bytes INTEGER DEFAULT 0,
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create router status cache table
        c.execute('''
            CREATE TABLE IF NOT EXISTS router_status_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                info_json TEXT,
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_router_time ON ip_bandwidth_data (router_id, timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_ip ON ip_bandwidth_data (ip_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_mac ON ip_bandwidth_data (mac_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_router_status_time ON router_status_cache (last_checked)')
        
        conn.commit()
        conn.close()
        print(f"Fallback database initialized successfully at {fallback_db_path}")
        # Don't change the global db_path - keep using data/routers.db
        return
    except Exception as e:
        print(f"Error initializing fallback database at {fallback_db_path}: {e}")
    
    # Last resort: use in-memory database
    db_path = ':memory:'
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS routers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER DEFAULT 8728,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("Using in-memory database (data will be lost on restart)")

# MikroTik API connection helper
def connect_to_router(host, port, username, password):
    try:
        connection = routeros_api.RouterOsApiPool(
            host,
            port=port,
            username=username,
            password=password,
            plaintext_login=True
        )
        api = connection.get_api()
        return api, connection, None
    except Exception as e:
        error_msg = str(e)
        # Provide more specific error messages
        if "timed out" in error_msg.lower():
            return None, None, f"Connection timeout to {host}:{port}. Check network connectivity and firewall settings."
        elif "refused" in error_msg.lower():
            return None, None, f"Connection refused by {host}:{port}. Check if API service is enabled on the router."
        elif "no route" in error_msg.lower():
            return None, None, f"No route to host {host}. Check IP address and network connectivity."
        elif "wrong user name or password" in error_msg.lower() or "invalid user name or password" in error_msg.lower():
            return None, None, f"Authentication failed for user '{username}'. Check username and password."
        else:
            return None, None, f"Connection failed: {error_msg}"

def get_router_info(api):
    try:
        # Get system identity
        identity = api.get_resource('/system/identity')
        router_name = identity.get()[0]['name']
        
        # Get system resources
        resources = api.get_resource('/system/resource')
        resource_data = resources.get()[0]
        
        # Get uptime
        uptime = resource_data.get('uptime', 'N/A')
        
        # Get memory info
        total_memory = resource_data.get('total-memory', 'N/A')
        free_memory = resource_data.get('free-memory', 'N/A')
        used_memory = resource_data.get('used-memory', 'N/A')
        
        # Get CPU info
        cpu_load = resource_data.get('cpu-load', 'N/A')
        
        # Get firmware version
        version = resource_data.get('version', 'N/A')
        
        return {
            'name': router_name,
            'uptime': uptime,
            'total_memory': total_memory,
            'free_memory': free_memory,
            'used_memory': used_memory,
            'cpu_load': cpu_load,
            'version': version
        }
    except Exception as e:
        return {'error': str(e)}

def get_detailed_router_info(api):
    try:
        detailed_info = {}
        
        # Get system identity
        try:
            identity = api.get_resource('/system/identity')
            detailed_info['identity'] = identity.get()[0] if identity.get() else {}
        except Exception as e:
            detailed_info['identity'] = {}
            print(f"Warning: Could not get system identity: {e}")
        
        # Get system resources
        try:
            resources = api.get_resource('/system/resource')
            detailed_info['resources'] = resources.get()[0] if resources.get() else {}
        except Exception as e:
            detailed_info['resources'] = {}
            print(f"Warning: Could not get system resources: {e}")
        
        # Get system clock
        try:
            clock = api.get_resource('/system/clock')
            detailed_info['clock'] = clock.get()[0] if clock.get() else {}
        except Exception as e:
            detailed_info['clock'] = {}
            print(f"Warning: Could not get system clock: {e}")
        
        # Get IP addresses
        try:
            ip_addresses = api.get_resource('/ip/address')
            detailed_info['ip_addresses'] = ip_addresses.get() if ip_addresses.get() else []
        except Exception as e:
            detailed_info['ip_addresses'] = []
            print(f"Warning: Could not get IP addresses: {e}")
        
        # Get interfaces
        try:
            interfaces = api.get_resource('/interface')
            detailed_info['interfaces'] = interfaces.get() if interfaces.get() else []
        except Exception as e:
            detailed_info['interfaces'] = []
            print(f"Warning: Could not get interfaces: {e}")
        
        # Get DHCP leases (connected IPs)
        try:
            dhcp_leases = api.get_resource('/ip/dhcp-server/lease')
            detailed_info['dhcp_leases'] = dhcp_leases.get() if dhcp_leases.get() else []
        except Exception as e:
            detailed_info['dhcp_leases'] = []
            print(f"Warning: Could not get DHCP leases: {e}")
        
        # Get system health
        try:
            health = api.get_resource('/system/health')
            detailed_info['health'] = health.get()[0] if health.get() else {}
        except Exception as e:
            detailed_info['health'] = {}
            print(f"Warning: Could not get system health: {e}")
        
        # Get license information
        try:
            license_info = api.get_resource('/system/license')
            detailed_info['license'] = license_info.get()[0] if license_info.get() else {}
        except Exception as e:
            detailed_info['license'] = {}
            print(f"Warning: Could not get license information: {e}")
        
        return detailed_info
    except Exception as e:
        return {'error': str(e)}

def collect_ip_bandwidth_data(router_id, api):
    """Collect per-IP bandwidth data using MikroTik traffic monitoring - focus on internal IPs"""
    try:
        # Get IP traffic data from firewall accounting
        traffic_data = []
        
        # Try to get traffic from firewall accounting
        try:
            accounting = api.get_resource('/ip/accounting')
            traffic_data = accounting.get() if accounting.get() else []
        except Exception as e:
            print(f"Could not get IP accounting data: {e}")
        
        # If no accounting data, try to get from connection tracking
        if not traffic_data:
            try:
                connections = api.get_resource('/ip/firewall/connection')
                connection_data = connections.get() if connections.get() else []
                
                # Convert connection data to traffic format
                for conn in connection_data:
                    if conn.get('src-address') and conn.get('dst-address'):
                        # This is simplified - real implementation would need more complex tracking
                        traffic_data.append({
                            'src-address': conn['src-address'],
                            'dst-address': conn['dst-address'],
                            'bytes': conn.get('bytes', 0),
                            'packets': conn.get('packets', 0)
                        })
            except Exception as e:
                print(f"Could not get connection data: {e}")
        
        # Get ARP table for MAC addresses and hostnames
        arp_table = {}
        try:
            arp = api.get_resource('/ip/arp')
            arp_data = arp.get() if arp.get() else []
            for entry in arp_data:
                if entry.get('address'):
                    arp_table[entry['address']] = {
                        'mac_address': entry.get('mac-address'),
                        'hostname': entry.get('host-name')
                    }
        except Exception as e:
            print(f"Could not get ARP table: {e}")
        
        # Get DHCP leases to identify internal IPs
        internal_ips = set()
        try:
            dhcp_leases = api.get_resource('/ip/dhcp-server/lease')
            leases = dhcp_leases.get() if dhcp_leases.get() else []
            for lease in leases:
                if lease.get('address'):
                    internal_ips.add(lease['address'])
        except Exception as e:
            print(f"Could not get DHCP leases: {e}")
        
        # Get static IP addresses
        try:
            ip_addresses = api.get_resource('/ip/address')
            addresses = ip_addresses.get() if ip_addresses.get() else []
            for addr in addresses:
                if addr.get('address'):
                    # Extract IP from CIDR notation (e.g., "192.168.1.1/24" -> "192.168.1.1")
                    ip = addr['address'].split('/')[0]
                    internal_ips.add(ip)
        except Exception as e:
            print(f"Could not get IP addresses: {e}")
        
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Track unique IPs and their traffic - focus on internal IPs
        ip_traffic = {}
        
        for traffic in traffic_data:
            # Track source IP traffic (only for internal IPs)
            src_ip = traffic.get('src-address')
            if src_ip and src_ip in internal_ips:
                # Extract just the IP without port
                src_ip_clean = src_ip.split(':')[0] if ':' in src_ip else src_ip
                if src_ip_clean not in ip_traffic:
                    ip_traffic[src_ip_clean] = {'rx_bytes': 0, 'tx_bytes': 0}
                ip_traffic[src_ip_clean]['tx_bytes'] += int(traffic.get('bytes', 0))
            
            # Track destination IP traffic (only for internal IPs)
            dst_ip = traffic.get('dst-address')
            if dst_ip and dst_ip in internal_ips:
                # Extract just the IP without port
                dst_ip_clean = dst_ip.split(':')[0] if ':' in dst_ip else dst_ip
                if dst_ip_clean not in ip_traffic:
                    ip_traffic[dst_ip_clean] = {'rx_bytes': 0, 'tx_bytes': 0}
                ip_traffic[dst_ip_clean]['rx_bytes'] += int(traffic.get('bytes', 0))
        
        # Store per-IP bandwidth data for internal IPs only
        for ip, traffic in ip_traffic.items():
            arp_info = arp_table.get(ip, {})
            c.execute('''
                INSERT INTO ip_bandwidth_data (router_id, ip_address, mac_address, hostname, rx_bytes, tx_bytes)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (router_id, ip, arp_info.get('mac_address'), arp_info.get('hostname'), 
                  traffic['rx_bytes'], traffic['tx_bytes']))
        
        conn.commit()
        conn.close()
        print(f"Collected IP bandwidth data for {len(ip_traffic)} internal IPs on router {router_id}")
        return True
    except Exception as e:
        print(f"Error collecting IP bandwidth data: {e}")
        return False

def update_router_status_cache(router_id, name, host, port, username, password):
    """Update router status cache for faster dashboard loading"""
    from datetime import datetime
    import json
    
    api, connection, error = connect_to_router(host, port, username, password)
    
    if api:
        info = get_router_info(api)
        connection.disconnect()
        status = 'online'
        router_info = json.dumps(info)
    else:
        status = 'offline'
        router_info = json.dumps({'error': error or 'Connection failed'})
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO router_status_cache (router_id, status, last_checked, info_json)
        VALUES (?, ?, ?, ?)
    ''', (router_id, status, datetime.now(), router_info))
    conn.commit()
    conn.close()
    
    return status, router_info

def get_ip_bandwidth_stats(router_id, time_periods):
    """Get per-IP bandwidth statistics for specified time periods - Zabbix-like intervals"""
    import datetime
    
    stats = {}
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Define time periods in minutes (Zabbix-like intervals)
    periods = {
        '1m': 1,
        '5m': 5,
        '15m': 15,
        '30m': 30,
        '1h': 60,
        '3h': 180,
        '6h': 360,
        '12h': 720,
        '24h': 1440,
        '3d': 4320,
        '1w': 10080
    }
    
    for period_name, period_minutes in periods.items():
        if period_name in time_periods:
            # Calculate time threshold
            threshold = datetime.datetime.now() - datetime.timedelta(minutes=period_minutes)
            
            # Get per-IP bandwidth data for this period
            c.execute('''
                SELECT ip_address, mac_address, hostname, 
                       SUM(rx_bytes) as total_rx, SUM(tx_bytes) as total_tx
                FROM ip_bandwidth_data 
                WHERE router_id = ? AND timestamp >= ?
                GROUP BY ip_address
                ORDER BY total_rx + total_tx DESC
            ''', (router_id, threshold))
            
            period_stats = {}
            for row in c.fetchall():
                ip_address, mac_address, hostname, total_rx, total_tx = row
                
                period_stats[ip_address] = {
                    'mac_address': mac_address,
                    'hostname': hostname,
                    'rx_bytes': total_rx or 0,
                    'tx_bytes': total_tx or 0,
                    'rx_mb': (total_rx / 1024 / 1024) if total_rx else 0,
                    'tx_mb': (total_tx / 1024 / 1024) if total_tx else 0
                }
            
            stats[period_name] = period_stats
    
    conn.close()
    return stats

@app.route('/')
def index():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM routers ORDER BY created_at DESC')
    routers = c.fetchall()
    conn.close()
    
    router_data = []
    for router in routers:
        router_id, name, host, port, username, password, created_at = router
        api, connection, error = connect_to_router(host, port, username, password)
        
        if api:
            info = get_router_info(api)
            connection.disconnect()
            router_data.append({
                'id': router_id,
                'name': name,
                'host': host,
                'port': port,
                'info': info
            })
        else:
            router_data.append({
                'id': router_id,
                'name': name,
                'host': host,
                'port': port,
                'info': {'error': error or 'Connection failed'}
            })
    
    # Create improved dashboard UI
    online_count = sum(1 for router in router_data if 'error' not in router['info'])
    total_count = len(router_data)
    
    router_cards = ''
    for router in router_data:
        status_class = 'success' if 'error' not in router['info'] else 'danger'
        status_text = 'Online' if 'error' not in router['info'] else 'Offline'
        status_icon = '✓' if 'error' not in router['info'] else '✗'
        
        # Format uptime if available
        uptime = router['info'].get('uptime', 'N/A')
        if uptime != 'N/A' and 'error' not in router['info']:
            # Try to parse MikroTik uptime format
            if 'd' in uptime or 'h' in uptime or 'm' in uptime:
                uptime = uptime.replace('d', 'd ').replace('h', 'h ').replace('m', 'm').strip()
        
        router_cards += f'''
        <div class="col-lg-6 col-xl-4 mb-4">
            <div class="card h-100 border-{status_class} shadow-sm">
                <div class="card-header d-flex justify-content-between align-items-center bg-{status_class} bg-opacity-10 border-{status_class}">
                    <h5 class="mb-0"><i class="fas fa-router me-2"></i>{router['name']}</h5>
                    <span class="badge bg-{status_class}">{status_icon} {status_text}</span>
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <small class="text-muted">Connection</small>
                        <p class="mb-1"><i class="fas fa-server me-2"></i>{router['host']}:{router['port']}</p>
                    </div>
                    '''
        
        if 'error' in router['info']:
            router_cards += f'''
                    <div class="alert alert-danger py-2 mb-0">
                        <small><i class="fas fa-exclamation-triangle me-1"></i><strong>Error:</strong> {router['info']['error']}</small>
                    </div>
            '''
        else:
            router_cards += f'''
                    <div class="row g-2">
                        <div class="col-6">
                            <small class="text-muted">Router Name</small>
                            <p class="mb-0"><i class="fas fa-tag me-1"></i>{router['info'].get('name', 'N/A')}</p>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Version</small>
                            <p class="mb-0"><i class="fas fa-code me-1"></i>{router['info'].get('version', 'N/A')}</p>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Uptime</small>
                            <p class="mb-0"><i class="fas fa-clock me-1"></i>{uptime}</p>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">CPU Load</small>
                            <p class="mb-0"><i class="fas fa-microchip me-1"></i>{router['info'].get('cpu_load', 'N/A')}%</p>
                        </div>
                    </div>
            '''
        
        router_cards += f'''
                </div>
                <div class="card-footer bg-transparent">
                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                        <a href="/monitor_router/{router['id']}" class="btn btn-primary btn-sm">
                            <i class="fas fa-chart-line me-1"></i>Monitor
                        </a>
                        <a href="/delete_router/{router['id']}" class="btn btn-outline-danger btn-sm" onclick="return confirm('Are you sure you want to delete {router['name']}?')">
                            <i class="fas fa-trash me-1"></i>Delete
                        </a>
                    </div>
                </div>
            </div>
        </div>
        '''
    
    return f'''
    <html>
    <head>
        <title>MikroTik Monitor Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            .card {{ transition: transform 0.2s; }}
            .card:hover {{ transform: translateY(-2px); }}
            .status-badge {{ font-size: 0.75rem; }}
            .router-stats {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        </style>
    </head>
    <body class="bg-light">
        <div class="container py-4">
            <div class="row mb-4">
                <div class="col">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h1 class="h3 mb-1"><i class="fas fa-network-wired text-primary me-2"></i>MikroTik Monitor</h1>
                            <p class="text-muted mb-0">Monitor and manage your MikroTik routers</p>
                        </div>
                        <a href="/add_router" class="btn btn-success">
                            <i class="fas fa-plus me-1"></i>Add Router
                        </a>
                    </div>
                </div>
            </div>
            
            <!-- Statistics Cards -->
            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card router-stats text-white">
                        <div class="card-body">
                            <div class="d-flex justify-content-between">
                                <div>
                                    <h4 class="mb-0">{total_count}</h4>
                                    <p class="mb-0">Total Routers</p>
                                </div>
                                <div class="align-self-center">
                                    <i class="fas fa-server fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card bg-success text-white">
                        <div class="card-body">
                            <div class="d-flex justify-content-between">
                                <div>
                                    <h4 class="mb-0">{online_count}</h4>
                                    <p class="mb-0">Online</p>
                                </div>
                                <div class="align-self-center">
                                    <i class="fas fa-check-circle fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card bg-danger text-white">
                        <div class="card-body">
                            <div class="d-flex justify-content-between">
                                <div>
                                    <h4 class="mb-0">{total_count - online_count}</h4>
                                    <p class="mb-0">Offline</p>
                                </div>
                                <div class="align-self-center">
                                    <i class="fas fa-exclamation-triangle fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Router Cards -->
            <div class="row">
                {router_cards if router_cards else '<div class="col-12"><div class="card text-center py-5"><div class="card-body"><i class="fas fa-router fa-3x text-muted mb-3"></i><h4 class="text-muted">No Routers Added</h4><p class="text-muted">Get started by adding your first MikroTik router</p><a href="/add_router" class="btn btn-primary"><i class="fas fa-plus me-1"></i>Add Your First Router</a></div></div></div>'}
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/add_router', methods=['GET', 'POST'])
def add_router():
    if request.method == 'POST':
        name = request.form['name']
        host = request.form['host']
        port = request.form.get('port', 8728)
        username = request.form['username']
        password = request.form['password']
        
        # Validate port
        try:
            port = int(port)
        except ValueError:
            flash('Port must be a valid number', 'error')
            return render_template('add_router.html')
        
        # Validate username (MikroTik usernames shouldn't contain special characters)
        if not username or not username.strip():
            flash('Username cannot be empty', 'error')
            return render_template('add_router.html')
        
        # Check for common username issues
        if ' ' in username:
            flash('Username cannot contain spaces', 'error')
            return render_template('add_router.html')
        
        # Test connection first
        api, connection, error = connect_to_router(host, port, username, password)
        if api:
            # Connection successful, save to database
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute('INSERT INTO routers (name, host, port, username, password) VALUES (?, ?, ?, ?, ?)',
                     (name, host, port, username, password))
            conn.commit()
            conn.close()
            connection.disconnect()
            flash('Router connected and added successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'Failed to connect to router: {error}', 'error')
    
    # Return simple add router form to avoid Python 3.14 template issues
    return '''
    <html>
    <head>
        <title>Add Router</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-4">
            <h1>Add New Router</h1>
            
            <div class="card">
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="name" class="form-label">Router Name</label>
                            <input type="text" class="form-control" id="name" name="name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="host" class="form-label">Host/IP Address</label>
                            <input type="text" class="form-control" id="host" name="host" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="port" class="form-label">Port</label>
                            <input type="number" class="form-control" id="port" name="port" value="8728">
                        </div>
                        
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        
                        <button type="submit" class="btn btn-primary">Add Router</button>
                        <a href="/" class="btn btn-secondary">Cancel</a>
                    </form>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/delete_router/<int:router_id>')
def delete_router(router_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('DELETE FROM routers WHERE id = ?', (router_id,))
    conn.commit()
    conn.close()
    flash('Router deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/refresh_router/<int:router_id>')
def refresh_router(router_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM routers WHERE id = ?', (router_id,))
    router = c.fetchone()
    conn.close()
    
    if router:
        router_id, name, host, port, username, password, created_at = router
        status, router_info = update_router_status_cache(router_id, name, host, port, username, password)
        
        if status == 'online':
            flash('Router information refreshed!', 'success')
        else:
            flash(f'Failed to connect to router', 'error')
    
    return redirect(url_for('index'))

@app.route('/monitor_router/<int:router_id>')
def monitor_router(router_id):
    # Get selected time period from query parameter, default to 1h
    selected_period = request.args.get('period', '1h')
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM routers WHERE id = ?', (router_id,))
    router = c.fetchone()
    conn.close()
    
    if not router:
        flash('Router not found', 'error')
        return redirect(url_for('index'))
    
    router_id, name, host, port, username, password, created_at = router
    api, connection, error = connect_to_router(host, port, username, password)
    
    if api:
        # Get essential information only - skip detailed collection
        basic_info = get_router_info(api)
        
        # Get DHCP leases for IP monitoring
        try:
            dhcp_leases = api.get_resource('/ip/dhcp-server/lease')
            dhcp_data = dhcp_leases.get() if dhcp_leases.get() else []
        except Exception as e:
            dhcp_data = []
            print(f"Warning: Could not get DHCP leases: {e}")
        
        connection.disconnect()
        
        if 'error' in basic_info:
            flash(f'Error getting router information: {basic_info["error"]}', 'error')
            return redirect(url_for('index'))
        
        # Get per-IP bandwidth statistics for selected time period only
        bandwidth_stats = get_ip_bandwidth_stats(router_id, [selected_period])
        
        # Define available time periods for dropdown
        time_periods = [
            ('1m', 'Last 1 minute'),
            ('5m', 'Last 5 minutes'), 
            ('15m', 'Last 15 minutes'),
            ('30m', 'Last 30 minutes'),
            ('1h', 'Last 1 hour'),
            ('3h', 'Last 3 hours'),
            ('6h', 'Last 6 hours'),
            ('12h', 'Last 12 hours'),
            ('24h', 'Last 24 hours'),
            ('3d', 'Last 3 days'),
            ('1w', 'Last 1 week')
        ]
        
        # Create enhanced monitor page with detailed router information
        bandwidth_table = ''
        total_ips = 0
        total_traffic = 0
        
        if selected_period in bandwidth_stats and bandwidth_stats[selected_period]:
            for ip, data in bandwidth_stats[selected_period].items():
                total_traffic += data.get('rx_mb', 0) + data.get('tx_mb', 0)
                bandwidth_table += f'''
                <tr>
                    <td><code>{ip}</code></td>
                    <td><small>{data.get('mac_address', '')}</small></td>
                    <td>{data.get('hostname', '')}</td>
                    <td class="text-end">{data.get('tx_mb', 0):.2f}</td>
                    <td class="text-end">{data.get('rx_mb', 0):.2f}</td>
                    <td class="text-end fw-bold">{data.get('rx_mb', 0) + data.get('tx_mb', 0):.2f}</td>
                </tr>
                '''
            total_ips = len(bandwidth_stats[selected_period])
        
        return f'''
        <html>
        <head>
            <title>Monitor - {name}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <style>
                .card {{ transition: transform 0.2s; }}
                .card:hover {{ transform: translateY(-1px); }}
                .info-card {{ border-left: 4px solid #0d6efd; }}
                .stats-card {{ border-left: 4px solid #198754; }}
                .traffic-card {{ border-left: 4px solid #6f42c1; }}
                .progress {{ height: 8px; }}
                .table-sm th, .table-sm td {{ padding: 0.5rem; }}
            </style>
        </head>
        <body class="bg-light">
            <div class="container py-4">
                <!-- Header -->
                <div class="row mb-4">
                    <div class="col">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h1 class="h3 mb-1"><i class="fas fa-chart-line text-primary me-2"></i>{name}</h1>
                                <p class="text-muted mb-0">
                                    <i class="fas fa-server me-1"></i>{host}:{port}
                                    <span class="badge bg-success ms-2"><i class="fas fa-check me-1"></i>Online</span>
                                </p>
                            </div>
                            <a href="/" class="btn btn-outline-primary">
                                <i class="fas fa-arrow-left me-1"></i>Dashboard
                            </a>
                        </div>
                    </div>
                </div>
                
                <!-- Router Information Cards -->
                <div class="row mb-4">
                    <div class="col-md-4 mb-3">
                        <div class="card info-card h-100">
                            <div class="card-body">
                                <h6 class="card-title text-muted"><i class="fas fa-info-circle me-2"></i>Basic Info</h6>
                                <div class="row g-2">
                                    <div class="col-12">
                                        <small class="text-muted">Router Identity</small>
                                        <p class="mb-0"><i class="fas fa-tag me-1"></i>{basic_info.get('name', 'N/A')}</p>
                                    </div>
                                    <div class="col-12">
                                        <small class="text-muted">Firmware Version</small>
                                        <p class="mb-0"><i class="fas fa-code me-1"></i>{basic_info.get('version', 'N/A')}</p>
                                    </div>
                                    <div class="col-12">
                                        <small class="text-muted">Uptime</small>
                                        <p class="mb-0"><i class="fas fa-clock me-1"></i>{basic_info.get('uptime', 'N/A')}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4 mb-3">
                        <div class="card stats-card h-100">
                            <div class="card-body">
                                <h6 class="card-title text-muted"><i class="fas fa-microchip me-2"></i>System Resources</h6>
                                <div class="row g-2">
                                    <div class="col-12">
                                        <small class="text-muted">CPU Load</small>
                                        <div class="d-flex align-items-center">
                                            <div class="flex-grow-1">
                                                <div class="progress">
                                                    <div class="progress-bar bg-success" role="progressbar" 
                                                         style="width: {basic_info.get('cpu_load', 0)}%" 
                                                         aria-valuenow="{basic_info.get('cpu_load', 0)}" 
                                                         aria-valuemin="0" 
                                                         aria-valuemax="100">
                                                    </div>
                                                </div>
                                            </div>
                                            <small class="ms-2 fw-bold">{basic_info.get('cpu_load', 'N/A')}%</small>
                                        </div>
                                    </div>
                                    <div class="col-12">
                                        <small class="text-muted">Memory Usage</small>
                                        <div class="d-flex align-items-center">
                                            <div class="flex-grow-1">
                                                <div class="progress">
                                                    <div class="progress-bar bg-info" role="progressbar" 
                                                         style="width: 50%" 
                                                         aria-valuenow="50" 
                                                         aria-valuemin="0" 
                                                         aria-valuemax="100">
                                                    </div>
                                                </div>
                                            </div>
                                            <small class="ms-2 fw-bold">50%</small>
                                        </div>
                                    </div>
                                    <div class="col-12">
                                        <small class="text-muted">Memory Details</small>
                                        <p class="mb-0 small">Used: {basic_info.get('used_memory', 'N/A')} / Total: {basic_info.get('total_memory', 'N/A')}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4 mb-3">
                        <div class="card traffic-card h-100">
                            <div class="card-body">
                                <h6 class="card-title text-muted"><i class="fas fa-network-wired me-2"></i>Traffic Overview</h6>
                                <div class="text-center py-3">
                                    <h3 class="text-primary mb-1">{total_ips}</h3>
                                    <p class="text-muted mb-0">Active IPs</p>
                                </div>
                                <div class="text-center">
                                    <h4 class="text-success mb-1">{total_traffic:.2f} MB</h4>
                                    <p class="text-muted mb-0">Total Traffic</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Bandwidth Monitoring -->
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0"><i class="fas fa-chart-bar me-2"></i>IP Bandwidth Monitoring</h5>
                        <div class="d-flex align-items-center">
                            <small class="text-muted me-2">Time Period:</small>
                            <select class="form-select form-select-sm" style="width: auto;" onchange="window.location.href='/monitor_router/{router_id}?period=' + this.value">
                                <option value="1m" {'selected' if selected_period == '1m' else ''}>Last 1 minute</option>
                                <option value="5m" {'selected' if selected_period == '5m' else ''}>Last 5 minutes</option>
                                <option value="15m" {'selected' if selected_period == '15m' else ''}>Last 15 minutes</option>
                                <option value="30m" {'selected' if selected_period == '30m' else ''}>Last 30 minutes</option>
                                <option value="1h" {'selected' if selected_period == '1h' else ''}>Last 1 hour</option>
                                <option value="3h" {'selected' if selected_period == '3h' else ''}>Last 3 hours</option>
                                <option value="6h" {'selected' if selected_period == '6h' else ''}>Last 6 hours</option>
                                <option value="12h" {'selected' if selected_period == '12h' else ''}>Last 12 hours</option>
                                <option value="24h" {'selected' if selected_period == '24h' else ''}>Last 24 hours</option>
                                <option value="3d" {'selected' if selected_period == '3d' else ''}>Last 3 days</option>
                                <option value="1w" {'selected' if selected_period == '1w' else ''}>Last 1 week</option>
                            </select>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm table-hover">
                                <thead class="table-light">
                                    <tr>
                                        <th>IP Address</th>
                                        <th>MAC Address</th>
                                        <th>Hostname</th>
                                        <th class="text-end">Upload (MB)</th>
                                        <th class="text-end">Download (MB)</th>
                                        <th class="text-end">Total (MB)</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {bandwidth_table if bandwidth_table else '<tr><td colspan="6" class="text-center text-muted py-4"><i class="fas fa-inbox fa-2x mb-2"></i><br>No bandwidth data available for selected period</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        '''
    else:
        # Return simple error response to avoid Python 3.14 compatibility issues
        return f'''
        <html>
        <head><title>Connection Error</title></head>
        <body>
            <h1>Connection Failed</h1>
            <p>Failed to connect to router: {error}</p>
            <p><a href="/">Return to Dashboard</a></p>
        </body>
        </html>
        ''', 200

if __name__ == '__main__':
    init_db()
    print(f"Starting Flask app with database at: {db_path}")
    app.run(host='0.0.0.0', port=8080, debug=True)