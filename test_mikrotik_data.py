#!/usr/bin/env python3
"""
Test script to check what data structure MikroTik API returns for DHCP and ARP
"""

import routeros_api
import os

def test_mikrotik_data():
    # Get connection details from environment or use defaults
    host = os.environ.get('MIKROTIK_HOST', '192.168.88.1')
    username = os.environ.get('MIKROTIK_USERNAME', 'admin')
    password = os.environ.get('MIKROTIK_PASSWORD', '')
    port = int(os.environ.get('MIKROTIK_PORT', '8728'))
    
    print(f"Testing connection to {host}:{port} as {username}")
    
    try:
        # Connect to MikroTik
        connection = routeros_api.RouterOsApiPool(
            host,
            port=port,
            username=username,
            password=password,
            plaintext_login=True
        )
        api = connection.get_api()
        
        print("\n=== DHCP Leases ===")
        try:
            dhcp_leases = api.get_resource('/ip/dhcp-server/lease')
            leases = dhcp_leases.get()
            print(f"Found {len(leases)} DHCP leases")
            if leases:
                for i, lease in enumerate(leases[:3]):  # Show first 3
                    print(f"Lease {i+1}: {lease}")
        except Exception as e:
            print(f"Error getting DHCP leases: {e}")
        
        print("\n=== ARP Table ===")
        try:
            arp = api.get_resource('/ip/arp')
            arp_data = arp.get()
            print(f"Found {len(arp_data)} ARP entries")
            if arp_data:
                for i, entry in enumerate(arp_data[:3]):  # Show first 3
                    print(f"ARP {i+1}: {entry}")
        except Exception as e:
            print(f"Error getting ARP table: {e}")
        
        connection.disconnect()
        
    except Exception as e:
        print(f"Connection failed: {e}")
        print("\nTo test with your MikroTik router, set these environment variables:")
        print("  export MIKROTIK_HOST=your.router.ip")
        print("  export MIKROTIK_USERNAME=your_username") 
        print("  export MIKROTIK_PASSWORD=your_password")

if __name__ == '__main__':
    test_mikrotik_data()