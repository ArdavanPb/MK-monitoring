#!/bin/bash

# Script to restart the Flask application with the latest code

echo "Stopping any running Flask applications..."

# Try to stop Flask apps (may require sudo)
pkill -f "python.*app.py" 2>/dev/null || echo "No Flask processes found or couldn't stop them"

# Wait a moment for processes to stop
sleep 2

echo "Starting Flask application with latest code..."
cd /home/ap/projects/mk-monitoring
source venv/bin/activate
python app.py &

echo "Flask application started in background"
echo "PID: $!"
echo "Check http://localhost:8080 to verify it's working"