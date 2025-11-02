# Zabbix-Style Bandwidth Chart Feature

## Overview
I've implemented a comprehensive Zabbix-style bandwidth chart feature that allows users to visualize historical bandwidth usage for individual IP addresses.

## Features Added

### 1. **Interactive Bandwidth Charts**
- **Line charts** showing upload/download bandwidth over time
- **Multiple time periods**: 1h, 3h, 6h, 12h, 24h, 3d, 1w
- **Real-time data** from the bandwidth monitoring database
- **Smooth animations** and professional styling

### 2. **User Interface**
- **Clickable table rows** - Click any IP address in the bandwidth table to view its chart
- **Dynamic chart section** - Appears above the table when viewing a chart
- **Time period selector** - Change chart time range without reloading
- **Close button** - Hide the chart when done
- **Auto-scroll** - Automatically scrolls to chart when opened

### 3. **Technical Implementation**

#### Backend (app.py)
- **New API endpoint**: `/api/chart/bandwidth/<router_id>`
- **Smart data aggregation**: 
  - 1-minute intervals for short periods (1h, 3h)
  - 5-minute intervals for longer periods (6h+)
- **Efficient SQL queries** with proper time grouping
- **Error handling** for missing data

#### Frontend (monitor.html)
- **Chart.js integration** for professional charts
- **Axios** for API calls
- **Responsive design** that works on all screen sizes
- **Loading states** and error messages

### 4. **Chart Features**
- **Dual line display** - Upload (red) and Download (blue) lines
- **Area fill** - Semi-transparent fill under lines
- **Interactive tooltips** - Hover for detailed values
- **Time-based X-axis** - Proper time formatting
- **MB-based Y-axis** - Consistent with table display
- **Professional styling** - Clean, modern appearance

## How It Works

1. **User clicks** on any IP address row in the bandwidth table
2. **Chart section appears** above the table with loading state
3. **API call fetches** historical data for the selected IP
4. **Chart renders** with upload/download lines
5. **User can change** time period using dropdown
6. **Chart updates** dynamically without page reload
7. **User closes** chart when finished

## API Endpoint

```
GET /api/chart/bandwidth/<router_id>?ip=<ip_address>&period=<time_period>
```

**Parameters:**
- `ip`: IP address to chart (required)
- `period`: Time period (1h, 3h, 6h, 12h, 24h, 3d, 1w)

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "timestamp": "2024-01-01 12:00:00",
      "download_mb": 1.5,
      "upload_mb": 0.8,
      "total_mb": 2.3
    }
  ],
  "ip_address": "192.168.1.100",
  "time_period": "1h"
}
```

## Data Aggregation

- **Short periods (1h, 3h)**: Data grouped by 1-minute intervals
- **Long periods (6h+)**: Data grouped by 5-minute intervals for performance
- **MB conversion**: Bytes converted to megabytes for consistency
- **Time formatting**: Proper timestamp handling and display

## Benefits

1. **Zabbix-like Experience** - Familiar charting interface for network monitoring
2. **Historical Analysis** - See bandwidth patterns over time
3. **Troubleshooting** - Identify bandwidth spikes and issues
4. **Performance Monitoring** - Track usage trends for capacity planning
5. **User-Friendly** - Intuitive click-to-chart interaction

The implementation provides a professional, Zabbix-style bandwidth monitoring experience that enhances the existing per-IP bandwidth tracking functionality.