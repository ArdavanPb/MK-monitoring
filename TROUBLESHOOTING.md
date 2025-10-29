# MikroTik Router Connection Troubleshooting

## Common Connection Issues and Solutions

### 1. **Network Connectivity Issues**

**Problem**: "Connection timeout" or "No route to host"

**Solutions**:
- Verify the router IP address is correct
- Check if the application can reach the router network
- Test basic connectivity: `ping <router_ip>`
- Ensure both devices are on the same network
- Check firewall settings on both the router and application server

### 2. **API Service Not Enabled**

**Problem**: "Connection refused"

**Solutions**:
1. **Enable API Service on MikroTik**:
   ```
   /ip service
   set api disabled=no
   set api port=8728
   ```

2. **Check API Service Status**:
   ```
   /ip service print
   ```

### 3. **API User Permissions**

**Problem**: Authentication succeeds but API access denied

**Solutions**:
1. **Create API User**:
   ```
   /user add name=api-user password=your-password group=full
   ```

2. **Enable API for User**:
   ```
   /user set api-user allowed-address=0.0.0.0/0
   ```

### 4. **Port Issues**

**Problem**: Connection fails even with correct credentials

**Solutions**:
- Default API port is **8728**
- Check if port is changed in router configuration
- Verify port forwarding if connecting from external network
- Test with telnet: `telnet <router_ip> 8728`

### 5. **Router Configuration Checklist**

✅ **API Service Enabled**:
```
/ip service print
```

✅ **User with API Access**:
```
/user print
```

✅ **Firewall Rules**:
```
/ip firewall filter print
```

✅ **Network Connectivity**:
```
ping <router_ip>
```

### 6. **Testing Connection Manually**

You can test the connection manually using Python:

```python
import routeros_api

try:
    connection = routeros_api.RouterOsApiPool(
        '192.168.88.1',  # Your router IP
        port=8728,
        username='admin',  # Your username
        password='password',  # Your password
        plaintext_login=True,
        timeout=10
    )
    api = connection.get_api()
    print("Connection successful!")
    connection.disconnect()
except Exception as e:
    print(f"Connection failed: {e}")
```

### 7. **Security Considerations**

- Use dedicated API users with limited permissions
- Restrict API access to specific IP addresses
- Consider using SSL/TLS if available
- Regularly update router firmware

### 8. **Network Topology Issues**

- If running in Docker, ensure container can reach the router network
- Check if there are VLANs or network segmentation
- Verify subnet masks and routing

## Quick Diagnostic Steps

1. **Ping Test**: `ping <router_ip>`
2. **Port Test**: `telnet <router_ip> 8728`
3. **API Test**: Use the manual Python script above
4. **Router Check**: Verify API service and user permissions

If all else fails, try connecting from a different machine on the same network to isolate the issue.