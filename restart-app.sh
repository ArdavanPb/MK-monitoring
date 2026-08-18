#!/bin/bash

# Script to restart the Flask application with the latest code.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Stopping any running Flask applications..."
pkill -f "python.*app.py" 2>/dev/null || echo "No Flask processes found or couldn't stop them"

sleep 2

echo "Starting Flask application with latest code..."
cd "$SCRIPT_DIR"
if [ -d "venv" ]; then
    source venv/bin/activate
fi
python app.py &

echo "Flask application started in background"
echo "PID: $!"
echo "Check http://localhost:8080 to verify it's working"
