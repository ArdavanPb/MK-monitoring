#!/bin/bash

# Test if web interface is accessible

echo "Testing web interface accessibility..."

# Test local access (inside container)
echo "1. Testing local access (inside container)..."
if curl -f http://localhost:8080 > /dev/null 2>&1; then
    echo "   ✓ Web interface accessible inside container"
else
    echo "   ✗ Web interface NOT accessible inside container"
fi

# Test from host (if running)
echo "2. Testing from host..."
if curl -f http://localhost:8080 > /dev/null 2>&1; then
    echo "   ✓ Web interface accessible from host"
else
    echo "   ⚠ Web interface may not be accessible from host"
    echo "   Check if Docker port mapping is working:"
    echo "   - Run: docker ps"
    echo "   - Look for '0.0.0.0:8080->8080/tcp' in PORTS column"
fi

# Check running processes
echo "3. Checking running processes..."
ps aux | grep -E "(python|app.py)" | grep -v grep

echo "4. Checking network ports..."
netstat -tlnp | grep :8080 || echo "   No process listening on port 8080"