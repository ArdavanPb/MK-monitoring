#!/bin/bash

# Quick start script for MikroTik Router Monitoring
# This script provides the fastest way to get the application running

echo "🚀 Quick Start for MikroTik Router Monitoring"
echo ""

# Check if Docker is available
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo "📦 Starting with Docker..."
    docker-compose up -d
    echo ""
    echo "✅ Application started!"
    echo "🌐 Access at: http://localhost:8080"
    echo ""
    echo "To stop: docker-compose down"
    echo "To view logs: docker-compose logs -f"
else
    echo "🐍 Docker not available, using Python setup..."
    echo ""
    
    # Run setup
    ./setup.sh
    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "To start the application:"
    echo "  ./run.sh"
    echo ""
    echo "Then access at: http://localhost:8080"
fi