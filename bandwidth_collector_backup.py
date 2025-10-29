#!/usr/bin/env python3
"""
Background service to collect per-IP bandwidth data from MikroTik routers every minute
"""

import sqlite3
import routeros_api
import time
import schedule
import threading
from datetime import datetime

db_path = '/app/data/routers.db'

# Dictionary to store previous interface statistics for each router
router_interface_stats = {}

def collect_all_routers_bandwidth():
    """Collect bandwidth data for all routers in the database"""
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Get all routers
        c.execute('SELECT id, name, host, port, username, password FROM routers')
        routers = c.fetchall()
        conn.close()
        
        for router in routers:
            router_id, name, host, port, username, password = router
            print(f"[{datetime.now()}] Collecting bandwidth data for {name} ({host})")
            
            try:
                # Connect to router
                connection = routeros_api.RouterOsApiPool(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    plaintext_login=True
                )
                api = connection.get_api()
                
                # Collect per-IP bandwidth data
                collect_ip_bandwidth_data(router_id, api)
                
                connection.disconnect()
                print(f"[{datetime.now()}] Successfully collected data for {name}")
                
            except Exception as e:
                print(f"[{datetime.now()}] Error collecting data for {name}: {e}")
        
    except Exception as e:
        print(f"[{datetime.now()}] Error in collector: {e}")

def collect_ip_bandwidth_data(router_id, api):
    """Collect per-IP bandwidth data using interface statistics and connection tracking"""
    try:
        # Get current interface statistics
        current_stats = {}
        total_rx_bytes = 0
        total_tx_bytes = 0
        
        try:
            interfaces = api.get_resource('/interface')
            interface_data = interfaces.get() if interfaces.get() else []
            for iface in interface_data:
                if iface.get('rx-byte') and iface.get('tx-byte'):
                    iface_name = iface.get('name')
                    rx_bytes = int(iface.get('rx-byte', 0))
                    tx_bytes = int(iface.get('tx-byte', 0))
                    current_stats[iface_name] = {'rx_bytes': rx_bytes, 'tx_bytes': tx_bytes}
                    total_rx_bytes += rx_bytes
                    total_tx_bytes += tx_bytes
        except Exception as e:
            print(f"Could not get interface statistics: {e}")
        
        # Calculate traffic delta from previous collection
        rx_delta = 0
        tx_delta = 0
        
        if router_id in router_interface_stats:
            prev_stats = router_interface_stats[router_id]
            prev_total_rx = prev_stats.get('total_rx_bytes', 0)
            prev_total_tx = prev_stats.get('total_tx_bytes', 0)
            
            # Calculate delta (handle counter wrap-around)
            rx_delta = max(0, total_rx_bytes - prev_total_rx)
            tx_delta = max(0, total_tx_bytes - prev_total_tx)
        
        # Store current stats for next calculation
        router_interface_stats[router_id] = {
            'total_rx_bytes': total_rx_bytes,
            'total_tx_bytes': total_tx_bytes,
            'timestamp': datetime.now()
        }
        
        # Get active IPs from connection tracking
        active_ips = set()
        try:
            connections = api.get_resource('/ip/firewall/connection')
            connection_data = connections.get() if connections.get() else []
            for conn in connection_data:
                src_ip = conn.get('src-address')
                dst_ip = conn.get('dst-address')
                if src_ip:
                    src_ip_clean = src_ip.split(':')[0] if ':' in src_ip else src_ip
                    active_ips.add(src_ip_clean)
                if dst_ip:
                    dst_ip_clean = dst_ip.split(':')[0] if ':' in dst_ip else dst_ip
                    active_ips.add(dst_ip_clean)
        except Exception as e:
            print(f"Could not get connection data: {e}")
        
        # Get internal IPs
        internal_ips = set()
        try:
            dhcp_leases = api.get_resource('/ip/dhcp-server/lease')
            leases = dhcp_leases.get() if dhcp_leases.get() else []
            for lease in leases:
                if lease.get('address'):
                    internal_ips.add(lease['address'])
        except Exception as e:
            print(f"Could not get DHCP leases: {e}")
        
        try:
            ip_addresses = api.get_resource('/ip/address')
            addresses = ip_addresses.get() if ip_addresses.get() else []
            for addr in addresses:
                if addr.get('address'):
                    ip = addr['address'].split('/')[0]
                    internal_ips.add(ip)
        except Exception as e:
            print(f"Could not get IP addresses: {e}")
        
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
        
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Calculate estimated traffic per active internal IP
        internal_active_ips = active_ips.intersection(internal_ips)
        
        # Store per-IP bandwidth data for internal IPs only
        if internal_active_ips and (rx_delta > 0 or tx_delta > 0):
            # Distribute total traffic among active internal IPs
            num_ips = len(internal_active_ips)
            estimated_rx_per_ip = rx_delta // num_ips
            estimated_tx_per_ip = tx_delta // num_ips
            
            for ip in internal_active_ips:
                arp_info = arp_table.get(ip, {})
                c.execute('''
                    INSERT INTO ip_bandwidth_data (router_id, ip_address, mac_address, hostname, rx_bytes, tx_bytes)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (router_id, ip, arp_info.get('mac_address'), arp_info.get('hostname'), 
                      estimated_rx_per_ip, estimated_tx_per_ip))
            
            print(f"Router {router_id}: Total RX={rx_delta} bytes, TX={tx_delta} bytes distributed among {num_ips} IPs")
        else:
            # Store minimal data for active IPs (fallback)
            for ip in internal_active_ips:
                arp_info = arp_table.get(ip, {})
                c.execute('''
                    INSERT INTO ip_bandwidth_data (router_id, ip_address, mac_address, hostname, rx_bytes, tx_bytes)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (router_id, ip, arp_info.get('mac_address'), arp_info.get('hostname'), 1, 1))
            
            if internal_active_ips:
                print(f"Router {router_id}: No traffic delta, stored minimal data for {len(internal_active_ips)} IPs")
        
        conn.commit()
        conn.close()
        print(f"Collected IP bandwidth data for {len(internal_active_ips)} internal IPs on router {router_id}")
        return True
    except Exception as e:
        print(f"Error collecting IP bandwidth data: {e}")
        return False

def run_scheduler():
    """Run the scheduler in a separate thread"""
    # Schedule data collection every minute
    schedule.every(1).minutes.do(collect_all_routers_bandwidth)
    
    print("Bandwidth collector started. Collecting data every minute...")
    
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    # Run the collector immediately on startup
    collect_all_routers_bandwidth()
    
    # Start the scheduler in a separate thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Bandwidth collector stopped.")