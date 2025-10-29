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
    """Collect per-IP bandwidth data using MikroTik traffic monitoring - focus on internal IPs"""
    try:
        # Get IP traffic data from firewall accounting
        traffic_data = []
        
        # Try to get traffic from firewall accounting
        try:
            accounting = api.get_resource('/ip/accounting')
            traffic_data = accounting.get() if accounting.get() else []
            print(f"Got {len(traffic_data)} entries from IP accounting")
        except Exception as e:
            print(f"Could not get IP accounting data: {e}")
        
        # If no accounting data, use connection tracking to identify active IPs
        if not traffic_data:
            try:
                connections = api.get_resource('/ip/firewall/connection')
                connection_data = connections.get() if connections.get() else []
                
                # Get active IPs from connection tracking
                active_ips = set()
                for conn in connection_data:
                    src_ip = conn.get('src-address')
                    dst_ip = conn.get('dst-address')
                    if src_ip:
                        src_ip_clean = src_ip.split(':')[0] if ':' in src_ip else src_ip
                        active_ips.add(src_ip_clean)
                    if dst_ip:
                        dst_ip_clean = dst_ip.split(':')[0] if ':' in dst_ip else dst_ip
                        active_ips.add(dst_ip_clean)
                
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
                
                # Only create traffic data for internal IPs that are active
                internal_active_ips = active_ips.intersection(internal_ips)
                
                for ip in internal_active_ips:
                    traffic_data.append({
                        'src-address': ip,
                        'dst-address': '0.0.0.0',
                        'bytes': 1,  # Minimal value to indicate activity
                        'packets': 1
                    })
                    traffic_data.append({
                        'src-address': '0.0.0.0',
                        'dst-address': ip,
                        'bytes': 1,  # Minimal value to indicate activity
                        'packets': 1
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
            if src_ip and src_ip != '0.0.0.0' and src_ip in internal_ips:
                # Extract just the IP without port
                src_ip_clean = src_ip.split(':')[0] if ':' in src_ip else src_ip
                if src_ip_clean not in ip_traffic:
                    ip_traffic[src_ip_clean] = {'rx_bytes': 0, 'tx_bytes': 0}
                ip_traffic[src_ip_clean]['tx_bytes'] += int(traffic.get('bytes', 0))
            
            # Track destination IP traffic (only for internal IPs)
            dst_ip = traffic.get('dst-address')
            if dst_ip and dst_ip != '0.0.0.0' and dst_ip in internal_ips:
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