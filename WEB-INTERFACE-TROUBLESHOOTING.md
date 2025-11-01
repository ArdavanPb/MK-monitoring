# Web Interface Not Accessible - Troubleshooting Guide

## Common Issues and Solutions

### 1. Port Mapping Issue
**Problem**: Docker container port not mapped to host

**Check**:
```bash
docker ps
```
Look for: `0.0.0.0:8080->8080/tcp` in PORTS column

**Fix**:
- Ensure `docker-compose.yml` has correct port mapping
- Try different host port:
  ```yaml
  ports:
    - "8081:8080"  # Map container port 8080 to host port 8081
  ```

### 2. Flask Not Binding Correctly
**Problem**: Flask only binding to localhost inside container

**Check**:
```bash
docker-compose exec mikrotik-monitor netstat -tlnp
```
Should show: `0.0.0.0:8080`

**Fix**:
- Ensure `app.py` has: `app.run(host='0.0.0.0', port=8080)`

### 3. Container Not Running
**Problem**: Container starts but exits immediately

**Check**:
```bash
docker-compose logs
```

**Fix**:
- Check for errors in logs
- Ensure both services start properly

### 4. Firewall/Network Issues
**Problem**: Host firewall blocking port

**Check**:
```bash
# On Linux
sudo ufw status
# On other systems, check firewall settings
```

**Fix**:
- Allow port 8080 through firewall
- Try accessing from different network

## Step-by-Step Diagnosis

### Step 1: Check Container Status
```bash
docker-compose ps
```
Should show "Up" status

### Step 2: Check Logs
```bash
docker-compose logs
```
Look for:
- "Starting Flask app"
- "Running on http://0.0.0.0:8080"
- Any error messages

### Step 3: Test Inside Container
```bash
docker-compose exec mikrotik-monitor curl http://localhost:8080
```
Should return HTML content

### Step 4: Test From Host
```bash
curl http://localhost:8080
```
If this fails but Step 3 works, it's a port mapping issue

### Step 5: Check Port Binding
```bash
docker-compose exec mikrotik-monitor netstat -tlnp | grep 8080
```
Should show process listening on 0.0.0.0:8080

## Quick Fixes

### Fix 1: Rebuild and Restart
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up
```

### Fix 2: Change Host Port
Edit `docker-compose.yml`:
```yaml
ports:
  - "8081:8080"
```
Then access: `http://localhost:8081`

### Fix 3: Use Different Network Mode
Edit `docker-compose.yml`:
```yaml
network_mode: "host"
```
Then remove ports section

## Common Error Messages

- "Connection refused" - Flask not running or wrong port
- "Cannot assign requested address" - Port already in use
- "No route to host" - Network/firewall issue

If none of these work, please share the exact output from `docker-compose logs`.