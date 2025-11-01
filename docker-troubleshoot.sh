#!/bin/bash

# Docker troubleshooting script

echo "=== Docker Troubleshooting ==="
echo

# Check if we're in Docker
echo "1. Checking Docker environment..."
if [ -f /.dockerenv ]; then
    echo "   ✓ Running inside Docker container"
else
    echo "   ⚠ Not running inside Docker container"
fi

# Check Python availability
echo "2. Checking Python..."
if command -v python &> /dev/null; then
    python --version
else
    echo "   ✗ Python not found"
fi

# Check directory structure
echo "3. Checking directory structure..."
ls -la /app/

# Check data directory
echo "4. Checking data directory..."
if [ -d /app/data ]; then
    echo "   ✓ /app/data exists"
    ls -la /app/data/
else
    echo "   ✗ /app/data does not exist"
fi

# Check database file
echo "5. Checking database file..."
if [ -f /app/data/routers.db ]; then
    echo "   ✓ /app/data/routers.db exists"
    echo "   File size: $(stat -c%s /app/data/routers.db) bytes"
else
    echo "   ✗ /app/data/routers.db does not exist"
fi

# Test Python imports
echo "6. Testing Python imports..."
python -c "
import sys
print('   Python path:', sys.prefix)

try:
    import sqlite3
    print('   ✓ sqlite3 import successful')
except ImportError as e:
    print('   ✗ sqlite3 import failed:', e)

try:
    import flask
    print('   ✓ flask import successful')
except ImportError as e:
    print('   ✗ flask import failed:', e)

try:
    import routeros_api
    print('   ✓ routeros_api import successful')
except ImportError as e:
    print('   ✗ routeros_api import failed:', e)
"

# Test database access
echo "7. Testing database access..."
python -c "
import sqlite3
import os

db_path = '/app/data/routers.db'
print(f'   Database path: {db_path}')
print(f'   Database exists: {os.path.exists(db_path)}')

if os.path.exists(db_path):
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT name FROM sqlite_master WHERE type=\"table\"')
        tables = [row[0] for row in c.fetchall()]
        print(f'   Tables in database: {tables}')
        conn.close()
    except Exception as e:
        print(f'   ✗ Database access failed: {e}')
else:
    print('   ⚠ Database file does not exist')
"

echo
echo "=== Troubleshooting Complete ==="