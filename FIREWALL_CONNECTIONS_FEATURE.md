# Live Firewall Connections Feature (Sophos/FortiGate Style)

## Overview
This feature provides real-time monitoring of active firewall connections exactly like Sophos XG "Current Activities" or FortiGate "Live Connections". It displays all active internet connections from internal networks to external destinations with detailed traffic information.

## Features

### Backend Implementation
- **New API Route**: `/api/firewall-connections/<router_id>` - Returns JSON data with live connection information
- **Data Source**: MikroTik RouterOS API path `/ip/firewall/connection` (same as Winbox > IP > Firewall > Connections tab)
- **Smart Filtering**: Only shows connections where source is internal (192.168.x.x, 10.x.x.x, 172.16-31.x.x) and destination is external
- **Service Detection**: Automatically identifies services based on port numbers (HTTPS, HTTP, DNS, SSH, etc.)
- **SNI Support**: If RouterOS v7+ has SNI tracking enabled, shows actual hostnames (youtube.com, netflix.com, etc.)

### Frontend Implementation
- **Monitor Page Integration**: "Live Connections (Firewall)" section on individual router monitor pages
- **Sophos/FortiGate Style**: Professional table layout matching enterprise firewall interfaces
- **Auto-Refresh**: Data updates every 30 seconds automatically
- **Manual Refresh**: Refresh button for on-demand updates
- **Connection Count**: Real-time badge showing number of active connections
- **Grouped View**: Collapsible accordion view grouped by source IP (like Sophos)

## Data Structure

Each connection entry includes:
- **Source IP**: Internal client IP address
- **Destination IP**: External server IP address
- **Protocol**: TCP/UDP/ICMP
- **Upload**: Data sent from client to server (human readable: KB/MB/GB)
- **Download**: Data received from server to client (human readable: KB/MB/GB)
- **Duration**: Connection uptime (e.g., "2h 15m 30s")
- **Service/App**: Service name based on port + SNI hostname if available

## Technical Implementation

### Backend Processing
1. **Fetch Connections**: Get all connections from `/ip/firewall/connection`
2. **Filter Internal Traffic**: Only show connections where source is internal and destination is external
3. **Parse Data**: 
   - Split bytes format "sent/received" into upload/download
   - Parse RouterOS duration format "2h15m30s"
   - Determine service name from port mapping
4. **SNI Detection**: Extract hostname from SNI field if available (RouterOS v7+)
5. **Group by Source IP**: Organize connections for the grouped view

### Frontend Features
- **Responsive Table**: Bootstrap-styled table with proper column alignment
- **Sorting**: Connections automatically sorted by total traffic volume (most bandwidth first)
- **Human Readable Sizes**: Automatic conversion of bytes to KB/MB/GB
- **Accordion Groups**: Click on source IP to expand/collapse all connections from that IP
- **Traffic Totals**: Per-IP upload/download totals in grouped view

## Usage

1. Navigate to the router monitor page
2. Scroll down to "Live Connections (Firewall)" section
3. View real-time active internet connections
4. Use "Refresh" button for manual updates
5. Click on source IP addresses in the grouped view to expand/collapse connections

## Example Output

```
┌─────────────────────────────────────────────────────────────┐
│ Src IP         Dst IP           Protocol  Upload     Download  Duration   Service/App     │
├─────────────────────────────────────────────────────────────┤
│ 192.168.88.105  104.18.20.45     TCP/443   89.7 MB    1.2 GB    2h 15m     HTTPS (Cloudflare) │
│ 192.168.88.107  216.58.206.174   TCP/443   45.3 MB    678 MB    45m        Google Services   │
│ 192.168.88.150  10.0.0.50        UDP/53     120 KB     890 KB    5m         DNS               │
└─────────────────────────────────────────────────────────────┘
```

## Router Requirements

- **MikroTik RouterOS**: Any version with API access
- **API Service**: Must be enabled on the router
- **SNI Tracking** (Optional): RouterOS v7+ with `/ip/firewall/connection/tracking` enabled and `sni-tracking=yes` for hostname detection

## Security

- Uses existing stored router credentials
- No sensitive data exposure
- Authentication required for all API endpoints
- Only shows external connections (internal traffic filtered out)