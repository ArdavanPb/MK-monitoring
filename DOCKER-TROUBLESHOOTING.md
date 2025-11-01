# Docker Troubleshooting Guide

## Common Docker Errors and Solutions

### 1. OperationalError: no such table: routers

**Cause**: Database not initialized before services start

**Solutions**:
- Rebuild with cache busting:
  ```bash
  docker-compose build --no-cache
  docker-compose up
  ```

- Use the simple startup script:
  ```bash
  # Edit Dockerfile CMD to use:
  CMD ["/bin/bash", "./docker-simple.sh"]
  ```

### 2. Permission Denied Errors

**Cause**: File permissions in Docker container

**Solutions**:
- Rebuild with proper permissions:
  ```bash
  docker-compose down
  docker-compose build --no-cache
  docker-compose up
  ```

### 3. Module Import Errors

**Cause**: Missing Python dependencies

**Solutions**:
- Check requirements.txt is copied properly
- Rebuild Docker image

## Quick Fix Commands

```bash
# Stop and remove containers
docker-compose down

# Rebuild with clean cache
docker-compose build --no-cache

# Start services
docker-compose up

# Check logs if issues persist
docker-compose logs
```

## Alternative Startup Methods

### Method 1: Simple Startup
Edit `Dockerfile` and change CMD to:
```dockerfile
CMD ["/bin/bash", "./docker-simple.sh"]
```

### Method 2: Direct Startup
Edit `Dockerfile` and change CMD to:
```dockerfile
CMD python bandwidth_collector.py & python app.py
```

## Debugging Steps

1. **Check Docker logs**:
   ```bash
   docker-compose logs
   ```

2. **Run troubleshooting script** (if included in container):
   ```bash
   docker-compose exec mikrotik-monitor ./docker-troubleshoot.sh
   ```

3. **Check container file structure**:
   ```bash
   docker-compose exec mikrotik-monitor ls -la /app/
   ```

4. **Test database manually**:
   ```bash
   docker-compose exec mikrotik-monitor python -c "import sqlite3; conn = sqlite3.connect('/app/data/routers.db'); c = conn.cursor(); c.execute('SELECT name FROM sqlite_master WHERE type=\"table\"'); print(c.fetchall())"
   ```

## If All Else Fails

1. **Complete clean rebuild**:
   ```bash
   docker-compose down -v  # Removes volumes too
   docker system prune -a  # Removes all unused containers, networks, images
   docker-compose build --no-cache
   docker-compose up
   ```

2. **Check host system permissions**:
   ```bash
   ls -la data/
   chmod 755 data/
   ```