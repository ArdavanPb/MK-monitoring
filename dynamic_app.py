from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime
import routeros_api
import json
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Global database path
db_path = 'data/routers.db'

# Ensure data directory exists
os.makedirs('data', exist_ok=True)

# Database setup
def init_db():
    global db_path
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Create routers table with enhanced fields
        c.execute('''
            CREATE TABLE IF NOT EXISTS routers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 8728,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                description TEXT,
                tags TEXT,
                enabled BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                router_id INTEGER PRIMARY KEY,
                status TEXT NOT NULL,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                router_info TEXT,
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create monitoring configuration table
        c.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER,
                config_name TEXT NOT NULL,
                config_value TEXT NOT NULL,
                config_type TEXT DEFAULT 'string',
                FOREIGN KEY (router_id) REFERENCES routers (id)
            )
        ''')
        
        # Create indexes for faster queries
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_router_time ON ip_bandwidth_data (router_id, timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_ip ON ip_bandwidth_data (ip_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_bandwidth_mac ON ip_bandwidth_data (mac_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_router_status_time ON router_status_cache (last_checked)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_routers_enabled ON routers (enabled)')
        
        conn.commit()
        conn.close()
        print(f"Database initialized successfully at {db_path}")
        
    except Exception as e:
        print(f"Error initializing database at {db_path}: {e}")

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
        if "timed out" in error_msg.lower():
            return None, None, f"Connection timeout to {host}:{port}"
        elif "refused" in error_msg.lower():
            return None, None, f"Connection refused by {host}:{port}"
        elif "no route" in error_msg.lower():
            return None, None, f"No route to host {host}"
        elif "wrong user name or password" in error_msg.lower() or "invalid user name or password" in error_msg.lower():
            return None, None, f"Authentication failed for user '{username}'"
        else:
            return None, None, f"Connection failed: {error_msg}"

def get_router_info(api):
    try:
        identity = api.get_resource('/system/identity')
        router_name = identity.get()[0]['name'] if identity.get() else 'Unknown'
        
        resources = api.get_resource('/system/resource')
        resource_data = resources.get()[0] if resources.get() else {}
        
        return {
            'name': router_name,
            'uptime': resource_data.get('uptime', 'N/A'),
            'total_memory': resource_data.get('total-memory', 'N/A'),
            'free_memory': resource_data.get('free-memory', 'N/A'),
            'used_memory': resource_data.get('used-memory', 'N/A'),
            'cpu_load': resource_data.get('cpu-load', 'N/A'),
            'version': resource_data.get('version', 'N/A')
        }
    except Exception as e:
        return {'error': str(e)}

def test_router_connection(host, port, username, password):
    api, connection, error = connect_to_router(host, port, username, password)
    
    if api:
        info = get_router_info(api)
        connection.disconnect()
        return True, info, None
    else:
        return False, None, error

def update_router_status_cache(router_id, name, host, port, username, password):
    from datetime import datetime
    
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

# Web Routes
@app.route('/')
def index():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get all enabled routers
    c.execute('SELECT id, name, host, port, description, tags FROM routers WHERE enabled = 1 ORDER BY name')
    routers = c.fetchall()
    
    # Get router status from cache
    c.execute('SELECT router_id, status, router_info FROM router_status_cache')
    status_cache = {row[0]: {'status': row[1], 'info': json.loads(row[2]) if row[2] else {}} for row in c.fetchall()}
    
    conn.close()
    
    router_data = []
    for router in routers:
        router_id, name, host, port, description, tags = router
        cache_entry = status_cache.get(router_id, {})
        
        router_data.append({
            'id': router_id,
            'name': name,
            'host': host,
            'port': port,
            'description': description,
            'tags': tags.split(',') if tags else [],
            'status': cache_entry.get('status', 'unknown'),
            'info': cache_entry.get('info', {})
        })
    
    return render_template('dynamic_index.html', routers=router_data)

@app.route('/add_router', methods=['GET', 'POST'])
def add_router():
    if request.method == 'POST':
        name = request.form['name']
        host = request.form['host']
        port = request.form.get('port', 8728)
        username = request.form['username']
        password = request.form['password']
        description = request.form.get('description', '')
        tags = request.form.get('tags', '')
        
        # Test connection first
        success, info, error = test_router_connection(host, port, username, password)
        
        if success:
            # Save to database
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO routers (name, host, port, username, password, description, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (name, host, port, username, password, description, tags))
            router_id = c.lastrowid
            
            # Update status cache
            update_router_status_cache(router_id, name, host, port, username, password)
            
            conn.commit()
            conn.close()
            
            flash(f'Router "{name}" added successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'Failed to connect to router: {error}', 'error')
    
    return render_template('dynamic_add_router.html')

@app.route('/router/<int:router_id>')
def router_details(router_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM routers WHERE id = ?', (router_id,))
    router = c.fetchone()
    conn.close()
    
    if not router:
        flash('Router not found', 'error')
        return redirect(url_for('index'))
    
    router_id, name, host, port, username, password, description, tags, enabled, created_at, updated_at = router
    
    # Test current connection
    success, info, error = test_router_connection(host, port, username, password)
    
    router_data = {
        'id': router_id,
        'name': name,
        'host': host,
        'port': port,
        'description': description,
        'tags': tags.split(',') if tags else [],
        'enabled': enabled,
        'created_at': created_at,
        'updated_at': updated_at
    }
    
    return render_template('dynamic_router_details.html', 
                         router=router_data, 
                         connection_info=info,
                         connection_error=error)

@app.route('/router/<int:router_id>/edit', methods=['GET', 'POST'])
def edit_router(router_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM routers WHERE id = ?', (router_id,))
    router = c.fetchone()
    
    if not router:
        conn.close()
        flash('Router not found', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form['name']
        host = request.form['host']
        port = request.form.get('port', 8728)
        username = request.form['username']
        password = request.form['password']
        description = request.form.get('description', '')
        tags = request.form.get('tags', '')
        enabled = request.form.get('enabled') == 'on'
        
        # If password is empty, keep existing password
        if not password:
            password = router[5]  # Existing password
        
        # Test connection if details changed
        if (host != router[2] or port != router[3] or username != router[4] or password != router[5]):
            success, info, error = test_router_connection(host, port, username, password)
            if not success:
                flash(f'Connection test failed: {error}', 'error')
                conn.close()
                return render_template('dynamic_edit_router.html', router=router)
        
        # Update router
        c.execute('''
            UPDATE routers 
            SET name=?, host=?, port=?, username=?, password=?, description=?, tags=?, enabled=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        ''', (name, host, port, username, password, description, tags, enabled, router_id))
        
        # Update status cache
        update_router_status_cache(router_id, name, host, port, username, password)
        
        conn.commit()
        conn.close()
        
        flash(f'Router "{name}" updated successfully!', 'success')
        return redirect(url_for('router_details', router_id=router_id))
    
    conn.close()
    
    router_data = {
        'id': router[0],
        'name': router[1],
        'host': router[2],
        'port': router[3],
        'username': router[4],
        'description': router[6],
        'tags': router[7],
        'enabled': router[8]
    }
    
    return render_template('dynamic_edit_router.html', router=router_data)

@app.route('/router/<int:router_id>/delete')
def delete_router(router_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get router name for flash message
    c.execute('SELECT name FROM routers WHERE id = ?', (router_id,))
    router = c.fetchone()
    
    if router:
        router_name = router[0]
        # Delete router and related data
        c.execute('DELETE FROM routers WHERE id = ?', (router_id,))
        c.execute('DELETE FROM router_status_cache WHERE router_id = ?', (router_id,))
        c.execute('DELETE FROM monitoring_config WHERE router_id = ?', (router_id,))
        
        conn.commit()
        conn.close()
        
        flash(f'Router "{router_name}" deleted successfully!', 'success')
    else:
        conn.close()
        flash('Router not found', 'error')
    
    return redirect(url_for('index'))

@app.route('/router/<int:router_id>/refresh')
def refresh_router(router_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM routers WHERE id = ?', (router_id,))
    router = c.fetchone()
    conn.close()
    
    if router:
        router_id, name, host, port, username, password, description, tags, enabled, created_at, updated_at = router
        status, router_info = update_router_status_cache(router_id, name, host, port, username, password)
        
        if status == 'online':
            flash('Router information refreshed!', 'success')
        else:
            flash('Router is offline', 'error')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    print(f"Starting Dynamic Router Manager at: http://127.0.0.1:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)