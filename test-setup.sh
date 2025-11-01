#!/bin/bash

# Test script to verify the setup works correctly

echo "🧪 Testing MikroTik Router Monitoring Setup..."
echo ""

# Check if required files exist
required_files=("app.py" "requirements.txt" "docker-compose.yml" "Dockerfile" "setup.sh" "run.sh")

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file found"
    else
        echo "❌ $file missing"
        exit 1
    fi
done

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "✅ Virtual environment exists"
else
    echo "⚠️  Virtual environment not found (run ./setup.sh to create)"
fi

# Check if data directory exists
if [ -d "data" ]; then
    echo "✅ Data directory exists"
else
    echo "⚠️  Data directory not found (will be created automatically)"
fi

echo ""
echo "✅ Setup verification complete!"
echo ""
echo "To start the application:"
echo "  ./quickstart.sh  # One-command setup"
echo "  docker-compose up -d  # Docker only"
echo "  ./run.sh  # Python only"