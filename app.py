from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from datetime import datetime
import routeros_api
import json
import os
import hashlib

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Default admin credentials (username: admin, password: admin)
DEFAULT_USERNAME = 'admin'
DEFAULT_PASSWORD = 'admin'

# Global database path - Docker compatible
import os
db_path = os.environ.get('DB_PATH', '/app/data/routers.db')

# For development outside Docker, use local data directory
if not os.path.exists('/app/data'):
    db_path = 'data/routers.db'

# Database setup
def init_db():
    global db_path
    
    # Use persistent data directory
    data_dir = os.path.dirname(db_path)
    os.makedirs(data_dir, exist_ok=True)
    
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
                router_info TEXT,
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create users table for authentication
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default admin user if not exists
        password_hash = hashlib.sha256(DEFAULT_PASSWORD.encode()).hexdigest()
        try:
            c.execute('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)', 
                     (DEFAULT_USERNAME, password_hash))
        except sqlite3.IntegrityError:
            pass  # User already exists
        
        # Check if router_info column exists (for backward compatibility)
        try:
            c.execute("SELECT router_info FROM router_status_cache LIMIT 1")
            print("Using existing router_info column")
        except sqlite3.OperationalError:
            # router_info column doesn't exist, check for info_json
            try:
                c.execute("SELECT info_json FROM router_status_cache LIMIT 1")
                print("Using existing info_json column")
            except sqlite3.OperationalError:
                # Neither column exists, add router_info column
                c.execute("ALTER TABLE router_status_cache ADD COLUMN router_info TEXT")
                print("Added router_info column to router_status_cache table")
        
        # Create system logs table for storing router logs
        c.execute('''
            CREATE TABLE IF NOT EXISTS router_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                topics TEXT,
                message TEXT NOT NULL,
                severity TEXT,
                stored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create log retention settings table
        c.execute('''
            CREATE TABLE IF NOT EXISTS log_retention_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                retention_days INTEGER DEFAULT 7,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create index for faster queries
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_router_time ON ip_bandwidth_data (router_id, timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_ip ON ip_bandwidth_data (ip_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_mac ON ip_bandwidth_data (mac_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_router_status_time ON router_status_cache (last_checked)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_router_logs_time ON router_logs (router_id, timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_router_logs_severity ON router_logs (severity)')
        
        conn.commit()
        conn.close()
        print(f"Database initialized successfully at {db_path}")
        
    except Exception as e:
        print(f"Error initializing database at {db_path}: {e}")
        raise

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
        router_name = identity.get()[0]['name'] if identity.get() else 'N/A'
        
        # Get system resources
        resources = api.get_resource('/system/resource')
        resource_data = resources.get()[0] if resources.get() else {}
        
        # Debug log the available resource fields
        print(f"Available resource fields: {list(resource_data.keys())}")
        print(f"Memory fields - Total: {resource_data.get('total-memory', 'N/A')}, Used: {resource_data.get('used-memory', 'N/A')}, Free: {resource_data.get('free-memory', 'N/A')}")
        print(f"Alternative memory fields - Size: {resource_data.get('memory-size', 'N/A')}, Used: {resource_data.get('memory-used', 'N/A')}, Free: {resource_data.get('memory-free', 'N/A')}")
        
        # Get uptime
        uptime = resource_data.get('uptime', 'N/A')
        
        # Get memory info with fallbacks
        total_memory = resource_data.get('total-memory', 'N/A')
        if total_memory == 'N/A':
            total_memory = resource_data.get('total_memory', 'N/A')
        if total_memory == 'N/A':
            total_memory = resource_data.get('memory-size', 'N/A')
        
        free_memory = resource_data.get('free-memory', 'N/A')
        if free_memory == 'N/A':
            free_memory = resource_data.get('free_memory', 'N/A')
        if free_memory == 'N/A':
            free_memory = resource_data.get('memory-free', 'N/A')
        
        used_memory = resource_data.get('used-memory', 'N/A')
        if used_memory == 'N/A':
            used_memory = resource_data.get('used_memory', 'N/A')
        if used_memory == 'N/A':
            used_memory = resource_data.get('memory-used', 'N/A')
        
        # Calculate used memory from total and free if not available
        if used_memory == 'N/A' and total_memory != 'N/A' and free_memory != 'N/A':
            try:
                total = int(total_memory)
                free = int(free_memory)
                used_memory = str(total - free)
                print(f"Calculated used memory: {used_memory} (total: {total_memory} - free: {free_memory})")
            except (ValueError, TypeError):
                used_memory = 'N/A'
        
        # Get CPU info - try multiple CPU load fields
        cpu_load = resource_data.get('cpu-load', 'N/A')
        if cpu_load == 'N/A':
            # Try alternative CPU load fields
            cpu_load = resource_data.get('cpu', 'N/A')
        
        cpu_count = resource_data.get('cpu-count', 'N/A')
        if cpu_count == 'N/A':
            cpu_count = resource_data.get('cpu-core-count', 'N/A')
        cpu_frequency = resource_data.get('cpu-frequency', 'N/A')
        
        # Get firmware version
        version = resource_data.get('version', 'N/A')
        
        # Get board information
        board_name = resource_data.get('board-name', 'N/A')
        if board_name == 'N/A':
            board_name = resource_data.get('hardware', 'N/A')
        
        architecture_name = resource_data.get('architecture-name', 'N/A')
        if architecture_name == 'N/A':
            architecture_name = resource_data.get('cpu-architecture', 'N/A')
        
        platform = resource_data.get('platform', 'N/A')
        
        # Get system package information
        build_time = resource_data.get('build-time', 'N/A')
        factory_software = resource_data.get('factory-software', 'N/A')
        
        # Calculate memory usage percentage
        memory_usage_percent = 'N/A'
        if total_memory != 'N/A' and used_memory != 'N/A' and total_memory != '0':
            try:
                memory_usage_percent = (int(used_memory) / int(total_memory) * 100)
                memory_usage_percent = round(memory_usage_percent, 1)
            except (ValueError, ZeroDivisionError):
                memory_usage_percent = 'N/A'
        
        result = {
            'name': router_name,
            'uptime': uptime,
            'total_memory': total_memory,
            'free_memory': free_memory,
            'used_memory': used_memory,
            'memory_usage_percent': memory_usage_percent,
            'cpu_load': cpu_load,
            'cpu_count': cpu_count,
            'cpu_frequency': cpu_frequency,
            'version': version,
            'board_name': board_name,
            'architecture_name': architecture_name,
            'platform': platform,
            'build_time': build_time,
            'factory_software': factory_software
        }
        
        # Debug log the final result
        print(f"Router info result: {result}")
        
        return result
    except Exception as e:
        print(f"Error in get_router_info: {e}")
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
            resource_data = resources.get()[0] if resources.get() else {}
            
            # Debug log available resource fields
            print(f"Detailed router info - Available resource fields: {list(resource_data.keys())}")
            
            # Try multiple CPU load fields
            cpu_load = resource_data.get('cpu-load', 'N/A')
            if cpu_load == 'N/A':
                cpu_load = resource_data.get('cpu', 'N/A')
            
            # Ensure CPU count is set
            cpu_count = resource_data.get('cpu-count', 'N/A')
            if cpu_count == 'N/A':
                cpu_count = resource_data.get('cpu-core-count', 'N/A')
            
            # Ensure architecture and board name are set
            architecture_name = resource_data.get('architecture-name', 'N/A')
            if architecture_name == 'N/A':
                architecture_name = resource_data.get('cpu-architecture', 'N/A')
            
            board_name = resource_data.get('board-name', 'N/A')
            if board_name == 'N/A':
                board_name = resource_data.get('hardware', 'N/A')
            
            # Ensure memory fields are set with fallbacks
            total_memory = resource_data.get('total-memory', 'N/A')
            if total_memory == 'N/A':
                total_memory = resource_data.get('total_memory', 'N/A')
            if total_memory == 'N/A':
                total_memory = resource_data.get('memory-size', 'N/A')
            
            free_memory = resource_data.get('free-memory', 'N/A')
            if free_memory == 'N/A':
                free_memory = resource_data.get('free_memory', 'N/A')
            if free_memory == 'N/A':
                free_memory = resource_data.get('memory-free', 'N/A')
            
            used_memory = resource_data.get('used-memory', 'N/A')
            if used_memory == 'N/A':
                used_memory = resource_data.get('used_memory', 'N/A')
            if used_memory == 'N/A':
                used_memory = resource_data.get('memory-used', 'N/A')
            
            # Calculate used memory from total and free if not available
            if used_memory == 'N/A' and total_memory != 'N/A' and free_memory != 'N/A':
                try:
                    total = int(total_memory)
                    free = int(free_memory)
                    used_memory = str(total - free)
                    print(f"Calculated used memory: {used_memory} (total: {total_memory} - free: {free_memory})")
                except (ValueError, TypeError):
                    used_memory = 'N/A'
            
            # Add the corrected values back to resource data
            resource_data['cpu_load'] = cpu_load
            resource_data['cpu_count'] = cpu_count
            resource_data['architecture_name'] = architecture_name
            resource_data['board_name'] = board_name
            resource_data['total_memory'] = total_memory
            resource_data['used_memory'] = used_memory
            resource_data['free_memory'] = free_memory
            detailed_info['resources'] = resource_data
            
            # Debug log specific values we're looking for
            print(f"CPU count: {resource_data.get('cpu-count', 'N/A')}")
            print(f"Architecture: {resource_data.get('architecture-name', 'N/A')}")
            print(f"Board name: {resource_data.get('board-name', 'N/A')}")
            print(f"Total memory: {resource_data.get('total-memory', 'N/A')}")
            print(f"Used memory: {resource_data.get('used-memory', 'N/A')}")
            print(f"Free memory: {resource_data.get('free-memory', 'N/A')}")
            print(f"Memory size: {resource_data.get('memory-size', 'N/A')}")
            print(f"Memory used: {resource_data.get('memory-used', 'N/A')}")
            print(f"Memory free: {resource_data.get('memory-free', 'N/A')}")
            
        except Exception as e:
            detailed_info['resources'] = {}
            print(f"Warning: Could not get system resources: {e}")
        
        # Get system clock and timezone
        try:
            clock = api.get_resource('/system/clock')
            clock_data = clock.get()[0] if clock.get() else {}
            
            # Debug log available clock fields
            print(f"Available clock fields: {list(clock_data.keys())}")
            
            # Try to get timezone from different fields
            timezone = clock_data.get('time-zone-name', 'N/A')
            if timezone == 'N/A':
                timezone = clock_data.get('time-zone-autodetect', 'N/A')
            if timezone == 'N/A':
                timezone = clock_data.get('time-zone', 'N/A')
            
            # Add timezone to clock data
            clock_data['time_zone_name'] = timezone
            detailed_info['clock'] = clock_data
            
            print(f"Timezone result: {timezone}")
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
            print(f"DHCP leases found: {len(detailed_info['dhcp_leases'])}")
            if detailed_info['dhcp_leases']:
                print(f"Sample DHCP lease: {detailed_info['dhcp_leases'][0]}")
        except Exception as e:
            detailed_info['dhcp_leases'] = []
            print(f"Warning: Could not get DHCP leases: {e}")
        
        # Get ARP table for MAC addresses and hostnames
        try:
            arp = api.get_resource('/ip/arp')
            arp_data = arp.get() if arp.get() else []
            detailed_info['arp_table'] = arp_data
            print(f"ARP entries found: {len(detailed_info['arp_table'])}")
            if detailed_info['arp_table']:
                print(f"Sample ARP entry: {detailed_info['arp_table'][0]}")
        except Exception as e:
            detailed_info['arp_table'] = []
            print(f"Warning: Could not get ARP table: {e}")
        
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
        
        # Get system logs
        try:
            logs = api.get_resource('/log')
            detailed_info['logs'] = logs.get() if logs.get() else []
            print(f"System logs found: {len(detailed_info['logs'])}")
        except Exception as e:
            detailed_info['logs'] = []
            print(f"Warning: Could not get system logs: {e}")
        
        return detailed_info
    except Exception as e:
        return {'error': str(e)}

def get_log_statistics(logs):
    """Analyze logs and return statistics by category and severity"""
    stats = {
        'total': len(logs),
        'categories': {},
        'severities': {
            'critical': 0,
            'warning': 0,
            'info': 0,
            'error': 0,
            'debug': 0,
            'other': 0
        }
    }
    
    for log in logs:
        # Count by category (topics)
        category = log.get('topics', 'other')
        if category not in stats['categories']:
            stats['categories'][category] = 0
        stats['categories'][category] += 1
        
        # Count by severity
        message = log.get('message', '').lower()
        if 'critical' in message or 'fatal' in message or 'emergency' in message:
            stats['severities']['critical'] += 1
        elif 'warning' in message or 'warn' in message:
            stats['severities']['warning'] += 1
        elif 'error' in message or 'err' in message:
            stats['severities']['error'] += 1
        elif 'info' in message:
            stats['severities']['info'] += 1
        elif 'debug' in message:
            stats['severities']['debug'] += 1
        else:
            stats['severities']['other'] += 1
    
    # Sort categories by count (descending)
    stats['categories'] = dict(sorted(stats['categories'].items(), key=lambda x: x[1], reverse=True))
    
    return stats

def save_router_logs(router_id, logs):
    """Save router logs to database"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    saved_count = 0
    for log in logs:
        timestamp = log.get('time', '')
        topics = log.get('topics', '')
        message = log.get('message', '')
        
        # Determine severity
        message_lower = message.lower()
        if 'critical' in message_lower or 'fatal' in message_lower or 'emergency' in message_lower:
            severity = 'critical'
        elif 'warning' in message_lower or 'warn' in message_lower:
            severity = 'warning'
        elif 'error' in message_lower or 'err' in message_lower:
            severity = 'error'
        elif 'info' in message_lower:
            severity = 'info'
        elif 'debug' in message_lower:
            severity = 'debug'
        else:
            severity = 'other'
        
        # Check if log already exists (based on timestamp and message)
        c.execute('SELECT id FROM router_logs WHERE router_id = ? AND timestamp = ? AND message = ?',
                 (router_id, timestamp, message))
        existing = c.fetchone()
        
        if not existing:
            c.execute('''
                INSERT INTO router_logs (router_id, timestamp, topics, message, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (router_id, timestamp, topics, message, severity))
            saved_count += 1
    
    conn.commit()
    conn.close()
    
    print(f"Saved {saved_count} new logs for router {router_id}")
    return saved_count

def get_log_retention_settings(router_id):
    """Get log retention settings for a router"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    c.execute('SELECT retention_days FROM log_retention_settings WHERE router_id = ?', (router_id,))
    result = c.fetchone()
    
    conn.close()
    
    if result:
        return result[0]
    else:
        # Default to 7 days if no setting exists
        return 7

def update_log_retention_settings(router_id, retention_days):
    """Update log retention settings for a router"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    c.execute('''
        INSERT OR REPLACE INTO log_retention_settings (router_id, retention_days)
        VALUES (?, ?)
    ''', (router_id, retention_days))
    
    conn.commit()
    conn.close()
    
    print(f"Updated log retention to {retention_days} days for router {router_id}")

def cleanup_old_logs(router_id):
    """Delete logs older than retention period"""
    import datetime
    
    retention_days = get_log_retention_settings(router_id)
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Convert cutoff_date to string format for comparison
    cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
    
    c.execute('DELETE FROM router_logs WHERE router_id = ? AND stored_at < ?', 
              (router_id, cutoff_str))
    deleted_count = c.rowcount
    
    conn.commit()
    conn.close()
    
    print(f"Cleaned up {deleted_count} old logs for router {router_id} (retention: {retention_days} days)")
    return deleted_count

def get_paginated_logs(router_id, page=1, per_page=50, severity_filter=None, search_term=None):
    """Get paginated logs with optional filtering"""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Build query with filters
    query = 'SELECT * FROM router_logs WHERE router_id = ?'
    params = [router_id]
    
    if severity_filter and severity_filter != 'all':
        query += ' AND severity = ?'
        params.append(severity_filter)
    
    if search_term:
        query += ' AND (message LIKE ? OR topics LIKE ?)'
        params.extend([f'%{search_term}%', f'%{search_term}%'])
    
    # Get total count
    count_query = query.replace('SELECT *', 'SELECT COUNT(*)')
    c.execute(count_query, params)
    total_logs = c.fetchone()[0]
    
    # Add ordering and pagination
    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    offset = (page - 1) * per_page
    params.extend([per_page, offset])
    
    c.execute(query, params)
    logs = c.fetchall()
    
    conn.close()
    
    # Calculate pagination info
    total_pages = (total_logs + per_page - 1) // per_page
    
    return {
        'logs': logs,
        'total_logs': total_logs,
        'page': page,
        'per_page': per_page,
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages
    }

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

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    return hash_password(password) == password_hash

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

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
        INSERT OR REPLACE INTO router_status_cache (router_id, status, last_checked, router_info)
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and verify_password(password, user[2]):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 4:
            flash('New password must be at least 4 characters long', 'error')
            return render_template('change_password.html')
        
        # Verify current password
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        
        if not user or not verify_password(current_password, user[0]):
            flash('Current password is incorrect', 'error')
            conn.close()
            return render_template('change_password.html')
        
        # Update password
        new_password_hash = hash_password(new_password)
        c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('change_password.html')

@app.route('/')
def index():
    # Redirect to login if not authenticated, otherwise show dashboard
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Show dashboard if authenticated
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
                'info': info,
                'status': 'online'
            })
        else:
            router_data.append({
                'id': router_id,
                'name': name,
                'host': host,
                'port': port,
                'info': {'error': error or 'Connection failed'},
                'status': 'offline'
            })
    
    return render_template('index.html', routers=router_data)

@app.route('/add_router', methods=['GET', 'POST'])
@login_required
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
    
    return render_template('add_router.html')

@app.route('/delete_router/<int:router_id>')
@login_required
def delete_router(router_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('DELETE FROM routers WHERE id = ?', (router_id,))
    conn.commit()
    conn.close()
    flash('Router deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/refresh_router/<int:router_id>')
@login_required
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
@login_required
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
        # Get detailed router information for the monitor page
        detailed_info = get_detailed_router_info(api)
        
        # Get log statistics
        log_stats = get_log_statistics(detailed_info.get('logs', []))
        
        connection.disconnect()
        
        if 'error' in detailed_info:
            flash(f'Error getting router information: {detailed_info["error"]}', 'error')
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
        
        # Enhanced monitor page with detailed router information
        
        return render_template('monitor.html', 
                             router={'id': router_id, 'name': name, 'host': host, 'port': port},
                             info=detailed_info,
                             bandwidth_stats=bandwidth_stats,
                             log_stats=log_stats,
                             selected_period=selected_period,
                             time_periods=time_periods)
    else:
        return render_template('error.html', error=error), 200

@app.route('/api/monitor/<int:router_id>')
@login_required
def api_monitor_router(router_id):
    """API endpoint for refreshing router monitor data"""
    # Get selected time period from query parameter, default to 1h
    selected_period = request.args.get('period', '1h')
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM routers WHERE id = ?', (router_id,))
    router = c.fetchone()
    conn.close()
    
    if not router:
        return jsonify({'success': False, 'error': 'Router not found'}), 404
    
    router_id, name, host, port, username, password, created_at = router
    api, connection, error = connect_to_router(host, port, username, password)
    
    if api:
        try:
            # Get updated system information
            system_info = get_router_info(api)
            
            # Get updated detailed information
            detailed_info = get_detailed_router_info(api)
            
            # Get updated bandwidth statistics
            bandwidth_stats = get_ip_bandwidth_stats(router_id, [selected_period])
            
            connection.disconnect()
            
            return jsonify({
                'success': True,
                'data': {
                    'system_info': system_info,
                    'tables': {
                        'ip_addresses': detailed_info.get('ip_addresses', []),
                        'dhcp_leases': detailed_info.get('dhcp_leases', []),
                        'arp_table': detailed_info.get('arp_table', [])
                    },
                    'bandwidth_stats': bandwidth_stats
                }
            })
            
        except Exception as e:
            if connection:
                connection.disconnect()
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({'success': False, 'error': error}), 500

def get_ip_bandwidth_history(router_id, ip_address, time_period):
    """Get historical bandwidth data for a specific IP address for charting"""
    import datetime
    
    # Define time periods in minutes
    periods = {
        '1h': 60,
        '3h': 180,
        '6h': 360,
        '12h': 720,
        '24h': 1440,
        '3d': 4320,
        '1w': 10080
    }
    
    if time_period not in periods:
        return {'error': 'Invalid time period'}
    
    period_minutes = periods[time_period]
    threshold = (datetime.datetime.now() - datetime.timedelta(minutes=period_minutes)).strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"Chart query: router_id={router_id}, ip={ip_address}, period={time_period}, threshold={threshold}")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        # Get data points grouped by time intervals
        if time_period in ['1h', '3h']:
            # For shorter periods, group by minute
            query = '''
                SELECT 
                    strftime('%Y-%m-%d %H:%M:00', timestamp) as time_bucket,
                    SUM(rx_bytes) as total_rx,
                    SUM(tx_bytes) as total_tx
                FROM ip_bandwidth_data 
                WHERE router_id = ? AND ip_address = ? AND timestamp >= ?
                GROUP BY time_bucket
                ORDER BY time_bucket
            '''
            print("Executing 1-minute interval query")
            c.execute(query, (router_id, ip_address, threshold))
        else:
            # For longer periods, group by 5-minute intervals
            query = '''
                SELECT 
                    strftime('%Y-%m-%d %H:%M:00', timestamp) as time_bucket,
                    SUM(rx_bytes) as total_rx,
                    SUM(tx_bytes) as total_tx
                FROM ip_bandwidth_data 
                WHERE router_id = ? AND ip_address = ? AND timestamp >= ?
                GROUP BY strftime('%Y-%m-%d %H', timestamp), (strftime('%M', timestamp) / 5)
                ORDER BY time_bucket
            '''
            print("Executing 5-minute interval query")
            c.execute(query, (router_id, ip_address, threshold))
        
        data_points = []
        rows = c.fetchall()
        print(f"Query returned {len(rows)} rows")
        
        for row in rows:
            time_bucket, total_rx, total_tx = row
            data_points.append({
                'timestamp': time_bucket,
                'download_mb': (total_rx or 0) / 1024 / 1024,
                'upload_mb': (total_tx or 0) / 1024 / 1024,
                'total_mb': ((total_rx or 0) + (total_tx or 0)) / 1024 / 1024
            })
        
        conn.close()
        return data_points
        
    except Exception as e:
        print(f"Error in get_ip_bandwidth_history: {e}")
        import traceback
        traceback.print_exc()
        conn.close()
        raise

@app.route('/update_log_retention/<int:router_id>', methods=['POST'])
@login_required
def update_log_retention(router_id):
    """Update log retention settings"""
    retention_days = request.form.get('retention_days', 7, type=int)
    
    # Validate retention days
    valid_retention = [1, 3, 7, 30, 90]
    if retention_days not in valid_retention:
        flash('Invalid retention period', 'error')
        return redirect(url_for('router_logs', router_id=router_id))
    
    update_log_retention_settings(router_id, retention_days)
    
    # Clean up old logs immediately after updating retention
    cleanup_old_logs(router_id)
    
    flash(f'Log retention updated to {retention_days} days', 'success')
    return redirect(url_for('router_logs', router_id=router_id))

@app.route('/export_logs_csv/<int:router_id>')
@login_required
def export_logs_csv(router_id):
    """Export router logs as CSV file"""
    import csv
    import io
    from datetime import datetime
    
    # Get filter parameters
    severity_filter = request.args.get('severity', 'all')
    search_term = request.args.get('search', '')
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Build query with filters
    query = 'SELECT timestamp, topics, message, severity, stored_at FROM router_logs WHERE router_id = ?'
    params = [router_id]
    
    if severity_filter and severity_filter != 'all':
        query += ' AND severity = ?'
        params.append(severity_filter)
    
    if search_term:
        query += ' AND (message LIKE ? OR topics LIKE ?)'
        params.extend([f'%{search_term}%', f'%{search_term}%'])
    
    query += ' ORDER BY timestamp DESC'
    
    c.execute(query, params)
    logs = c.fetchall()
    conn.close()
    
    # Get router name for filename
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT name FROM routers WHERE id = ?', (router_id,))
    router_name = c.fetchone()[0]
    conn.close()
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Timestamp', 'Category', 'Message', 'Severity', 'Stored At', 'Router Name'])
    
    # Write data
    for log in logs:
        timestamp, topics, message, severity, stored_at = log
        writer.writerow([timestamp, topics, message, severity, stored_at, router_name])
    
    # Prepare response
    output.seek(0)
    
    # Create filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{router_name}_logs_{timestamp}.csv"
    
    response = app.response_class(
        response=output.getvalue(),
        status=200,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )
    
    return response

@app.route('/api/chart/bandwidth/<int:router_id>')
@login_required
def api_chart_bandwidth(router_id):
    """API endpoint for bandwidth chart data"""
    ip_address = request.args.get('ip')
    time_period = request.args.get('period', '1h')
    
    print(f"Chart API called: router_id={router_id}, ip={ip_address}, period={time_period}")
    
    if not ip_address:
        return jsonify({'success': False, 'error': 'IP address parameter required'}), 400
    
    try:
        chart_data = get_ip_bandwidth_history(router_id, ip_address, time_period)
        print(f"Chart data retrieved: {len(chart_data) if chart_data else 0} points")
        
        # Check if we have any data
        if not chart_data:
            return jsonify({
                'success': True,
                'data': [],
                'ip_address': ip_address,
                'time_period': time_period,
                'message': 'No bandwidth data available for the selected time period'
            })
        
        return jsonify({
            'success': True,
            'data': chart_data,
            'ip_address': ip_address,
            'time_period': time_period
        })
    except Exception as e:
        print(f"Error in chart API: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/router_logs/<int:router_id>')
@login_required
def router_logs(router_id):
    """Page to show all router logs with pagination and retention settings"""
    # Get page and filter parameters
    page = request.args.get('page', 1, type=int)
    severity_filter = request.args.get('severity', 'all')
    search_term = request.args.get('search', '')
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM routers WHERE id = ?', (router_id,))
    router = c.fetchone()
    conn.close()
    
    if not router:
        flash('Router not found', 'error')
        return redirect(url_for('index'))
    
    router_id, name, host, port, username, password, created_at = router
    
    # Try to get fresh logs from router
    api, connection, error = connect_to_router(host, port, username, password)
    if api:
        try:
            # Get system logs from router
            logs_resource = api.get_resource('/log')
            fresh_logs = logs_resource.get() if logs_resource.get() else []
            
            # Save fresh logs to database
            saved_count = save_router_logs(router_id, fresh_logs)
            
            # Clean up old logs based on retention settings
            cleanup_old_logs(router_id)
            
            connection.disconnect()
            
            if saved_count > 0:
                flash(f'Updated {saved_count} new logs from router', 'success')
        except Exception as e:
            if connection:
                connection.disconnect()
            print(f"Warning: Could not fetch fresh logs: {e}")
    
    # Get paginated logs from database
    pagination_data = get_paginated_logs(router_id, page, 50, severity_filter, search_term)
    
    # Get log statistics from database
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get total statistics
    c.execute('SELECT COUNT(*) FROM router_logs WHERE router_id = ?', (router_id,))
    total_logs = c.fetchone()[0]
    
    # Get severity statistics
    c.execute('SELECT severity, COUNT(*) FROM router_logs WHERE router_id = ? GROUP BY severity', (router_id,))
    severity_stats = {}
    for severity, count in c.fetchall():
        severity_stats[severity] = count
    
    # Get category statistics
    c.execute('SELECT topics, COUNT(*) FROM router_logs WHERE router_id = ? GROUP BY topics', (router_id,))
    category_stats = {}
    for category, count in c.fetchall():
        category_stats[category] = count
    
    conn.close()
    
    # Get retention settings
    retention_days = get_log_retention_settings(router_id)
    
    return render_template('router_logs.html', 
                         router={'id': router_id, 'name': name, 'host': host, 'port': port},
                         logs=pagination_data['logs'],
                         log_stats={
                             'total': total_logs,
                             'severities': severity_stats,
                             'categories': category_stats
                         },
                         pagination=pagination_data,
                         retention_days=retention_days,
                         current_severity=severity_filter,
                         current_search=search_term)

if __name__ == '__main__':
    init_db()
    print(f"Starting Flask app with database at: {db_path}")
    app.run(host='0.0.0.0', port=8080, debug=True)