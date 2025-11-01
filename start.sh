#!/bin/bash

# Initialize database first by running app.py initialization
python -c "from app import init_db; init_db()"

# Wait a moment for database to be fully initialized
sleep 2

# Verify database is accessible and tables exist
python -c "
import sqlite3
try:
    conn = sqlite3.connect('data/routers.db')
    c = conn.cursor()
    c.execute('SELECT name FROM sqlite_master WHERE type=\"table\" AND name=\"routers\"')
    if c.fetchone():
        print('Database verification successful: routers table exists')
    else:
        print('ERROR: routers table not found after initialization')
        exit(1)
    conn.close()
except Exception as e:
    print(f'ERROR: Database verification failed: {e}')
    exit(1)
"

# Start bandwidth collector in background
python bandwidth_collector.py &

# Start Flask application
python app.py