#!/bin/sh

echo "Starting MK-Monitoring in Docker..."

# Create data directory if it doesn't exist
mkdir -p /app/data

# Initialize database
python -c "from app import init_db; init_db()"

# Start bandwidth collector in background
python bandwidth_collector.py &

# Start Flask application
python app.py