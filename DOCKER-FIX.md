# Docker OperationalError Fix

## Problem
When running on another server with Docker, you get:
```
sqlite3.OperationalError: no such table: routers
```

## Solution Applied

1. **Docker-specific startup script** (`docker-start.sh`) with:
   - Better error handling
   - Database verification before starting services
   - Proper timing delays

2. **Docker-compatible database paths** in both `app.py` and `bandwidth_collector.py`

3. **Improved Dockerfile** with:
   - Proper permissions
   - Executable scripts
   - Data directory creation

## How to Test

1. **Rebuild the Docker image**:
   ```bash
   docker-compose build --no-cache
   ```

2. **Start the services**:
   ```bash
   docker-compose up
   ```

3. **Check logs** for successful database initialization:
   ```
   Database verification successful
   Starting bandwidth collector...
   Starting Flask application...
   ```

## Key Changes

- `docker-start.sh` - New Docker-specific startup script
- `Dockerfile` - Updated to use Docker-specific script
- Database paths now detect Docker environment automatically
- Added proper error handling and verification

If the error persists, check the Docker logs with `docker-compose logs`.