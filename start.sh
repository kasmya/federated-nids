#!/bin/bash
# NIDS Web Dashboard - Start Script

cd "$(dirname "$0")"

echo "Starting NIDS Web Dashboard..."
echo ""

# Install dependencies if needed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "Installing dependencies..."
    pip3 install --user flask scapy pyshark
    echo ""
fi

# Start the server
python3 run_server.py

