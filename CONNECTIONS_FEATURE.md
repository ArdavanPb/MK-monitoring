# Real-Time Router Connections Feature

## Overview
This feature provides real-time monitoring of network connections for each MikroTik router in the dashboard. It displays detailed information about internal IP addresses, connected clients, and upstream connections.

## Features

### Backend Implementation
- **New API Route**: `/api/connections/<router_id>` - Returns JSON data with connection information
- **Data Collection**: 
  - Internal IP addresses from `/ip/address`
  - Connected clients from DHCP leases and ARP table
  - Upstream connections from routing table and interface hierarchy
- **Error Handling**: Graceful handling of API timeouts and connection failures

### Frontend Implementation
- **Dashboard Integration**: "View Connections" button on each router card
- **Responsive Design**: Bootstrap-based collapse sections with tables
- **Auto-Refresh**: Data refreshes every 30 seconds for visible sections
- **Manual Refresh**: Refresh button for on-demand updates

## Data Structure

Each connection entry includes:
- **IP Address**: Internal router IP
- **Interface**: Network interface name
- **Network**: CIDR notation (e.g., 192.168.1.1/24)
- **Clients**: List of connected devices with:
  - IP address
  - MAC address
  - Hostname
  - Connection status
- **Upstream**: Connection to external network:
  - Gateway IP
  - Interface
  - Connection type (default_route, bridge_parent, direct)

## Security
- Uses existing stored router credentials
- No sensitive data exposure
- Authentication required for all API endpoints

## Usage
1. Navigate to the dashboard
2. Click "View Connections" on any router card
3. View real-time connection data
4. Use "Refresh Connections" button for manual updates

## Technical Details
- **Backend**: Flask route with RouterOS API integration
- **Frontend**: Vanilla JavaScript with Axios for AJAX calls
- **Styling**: Bootstrap 5 with custom CSS
- **Auto-refresh**: 30-second intervals for visible sections