#!/bin/bash

# Docker startup script with better error handling
set -e  # Exit on any error

echo "Starting MK-Monitoring in Docker..."
echo "Platform: $(uname -s)"

# Create data directory if it doesn't exist
mkdir -p /app/data
chmod 755 /app/data

# Initialize database first with multiple attempts
for i in {1..3}; do
    echo "Initializing database (attempt $i/3)..."
    if python -c "from app import init_db; init_db()"; then
        echo "Database initialization successful"
        break
    else
        echo "Database initialization failed, retrying..."
        sleep 2
        if [ $i -eq 3 ]; then
            echo "ERROR: Database initialization failed after 3 attempts"
            exit 1
        fi
    fi
done

# Wait for database to be ready
echo "Waiting for database to initialize..."
sleep 2

# Verify database is accessible
echo "Verifying database..."
python -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('/app/data/routers.db')
    c = conn.cursor()
    c.execute('SELECT name FROM sqlite_master WHERE type=\"table\" AND name=\"routers\"')
    if c.fetchone():
        print('Database verification successful: routers table exists')
    else:
        print('ERROR: routers table not found')
        sys.exit(1)
    
    # Verify users table exists
    c.execute('SELECT name FROM sqlite_master WHERE type=\"table\" AND name=\"users\"')
    if c.fetchone():
        print('Users table exists')
    else:
        print('ERROR: users table not found')
        sys.exit(1)
    
    # Check if default admin user exists
    c.execute('SELECT username FROM users WHERE username=\"admin\"')
    if c.fetchone():
        print('Default admin user exists')
    else:
        print('ERROR: Default admin user not found')
        sys.exit(1)
        
    conn.close()
except Exception as e:
    print(f'ERROR: Database verification failed: {e}')
    sys.exit(1)
"

# Start bandwidth collector in background
echo "Starting bandwidth collector..."
python bandwidth_collector.py &

# Wait a moment for bandwidth collector to start
sleep 2

# Start Flask application
echo "Starting Flask application..."
python app.py &

# Wait for Flask to start and check if it's running
echo "Waiting for Flask to start..."
sleep 5

# Check if Flask is running
if curl -f http://localhost:8080 > /dev/null 2>&1; then
    echo "Flask application is running on http://localhost:8080"
    echo "Web interface should be accessible on host port 8080"
else
    echo "WARNING: Flask application may not be running properly"
    echo "Check Docker logs with: docker-compose logs"
fi

# Keep container running
echo "Container is running. Press Ctrl+C to stop."
while true; do sleep 60; done