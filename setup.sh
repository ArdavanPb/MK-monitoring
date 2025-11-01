#!/bin/bash

echo "Setting up MikroTik Router Monitoring Application..."

# Check if Python is available
if ! command -v python &> /dev/null; then
    echo "Error: Python is not installed or not in PATH"
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create data directory if it doesn't exist
mkdir -p data

echo ""
echo "✅ Setup complete!"
echo ""
echo "To run the application:"
echo "  ./run.sh"
echo "  # or manually:"
echo "  source venv/bin/activate"
echo "  python app.py"
echo ""
echo "To run the bandwidth collector:"
echo "  source venv/bin/activate"
echo "  python bandwidth_collector.py"
echo ""
echo "Then open your browser and go to: http://localhost:8080"