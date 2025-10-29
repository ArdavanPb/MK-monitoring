#!/bin/bash

echo "Setting up MikroTik Router Monitoring Application..."

# Create virtual environment
echo "Creating virtual environment..."
python -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "Setup complete!"
echo ""
echo "To run the application:"
echo "  source venv/bin/activate"
echo "  python app.py"
echo ""
echo "To run the bandwidth collector:"
echo "  source venv/bin/activate"
echo "  python bandwidth_collector.py"
echo ""
echo "Then open your browser and go to: http://localhost:8080"