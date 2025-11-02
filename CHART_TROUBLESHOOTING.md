# Bandwidth Chart Troubleshooting

## Common Issues and Solutions

### 1. "Error loading chart data: Request failed with status code 500"

**Cause**: This error occurs when there's a server-side issue with the chart API.

**Solutions**:
- ✅ **Fixed**: SQL query timestamp handling - The database stores timestamps as datetime strings, not UNIX timestamps
- ✅ **Fixed**: Proper error handling added to API endpoint
- ✅ **Fixed**: Debug logging added to identify issues

### 2. "No bandwidth data available for the selected time period"

**Cause**: The chart is working correctly, but there's no data for the selected IP address and time period.

**Solutions**:
- **Check data collection**: Make sure the bandwidth collector is running and collecting data
- **Verify time period**: Try longer time periods (24h, 3d, 1w) if you have older data
- **Check IP address**: Ensure the IP address exists in the bandwidth table

### 3. Chart shows no data points

**Cause**: The bandwidth data might be too old for the selected time period.

**Solutions**:
- **Use longer time periods**: If your data is from yesterday, use "Last 24 hours" or longer
- **Wait for data collection**: The bandwidth collector runs every minute, so wait for new data
- **Check router connectivity**: Ensure the router is online and the bandwidth collector can connect

## How the Chart Works

### Data Collection
- Bandwidth data is collected every minute by `bandwidth_collector.py`
- Data is stored in the `ip_bandwidth_data` table
- Each entry includes: IP address, RX bytes, TX bytes, timestamp

### Chart Data Aggregation
- **Short periods (1h, 3h)**: Data grouped by 1-minute intervals
- **Long periods (6h+)**: Data grouped by 5-minute intervals for performance
- **MB conversion**: Bytes converted to megabytes for display

### API Endpoint
```
GET /api/chart/bandwidth/<router_id>?ip=<ip_address>&period=<time_period>
```

## Testing the Chart

### 1. Verify Data Exists
```sql
-- Check if there's any bandwidth data
SELECT COUNT(*) FROM ip_bandwidth_data;

-- Check specific IP data
SELECT timestamp, rx_bytes, tx_bytes 
FROM ip_bandwidth_data 
WHERE ip_address = '192.168.1.100' 
ORDER BY timestamp DESC 
LIMIT 5;
```

### 2. Test the API Directly
```bash
# Replace with your actual router ID and IP address
curl "http://localhost:8080/api/chart/bandwidth/1?ip=192.168.2.10&period=1h"
```

### 3. Check Bandwidth Collector
```bash
# Make sure the bandwidth collector is running
ps aux | grep bandwidth_collector

# Check collector logs for errors
tail -f bandwidth_collector.log
```

## Recent Fixes Applied

1. **SQL Query Fix**: Corrected timestamp handling in chart data queries
2. **Error Handling**: Added proper exception handling and error messages
3. **Empty Data Handling**: Graceful handling when no data is available
4. **Debug Logging**: Added console logging for troubleshooting

## Expected Behavior

- ✅ **Click IP row** → Chart section appears
- ✅ **Loading spinner** → Shows while fetching data
- ✅ **Chart renders** → If data is available
- ✅ **No data message** → If no data for selected period
- ✅ **Error message** → If API fails
- ✅ **Time period change** → Chart updates dynamically

If you're still experiencing issues, check the Flask application logs for detailed error messages.