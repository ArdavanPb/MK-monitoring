#!/bin/bash

# Simple Docker startup script - starts services directly

# Create data directory
mkdir -p /app/data

# Start both services directly (let them handle their own initialization)
python bandwidth_collector.py &
python app.py