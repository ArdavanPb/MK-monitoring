#!/bin/bash

# Start bandwidth collector in background
python bandwidth_collector.py &

# Start Flask application
python app.py