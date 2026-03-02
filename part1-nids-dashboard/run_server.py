#!/usr/bin/env python3
"""
NIDS Web Dashboard - Server Launcher
Run this to start the NIDS Dashboard
"""

import os
import sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

print("=" * 50)
print("  NIDS Web Dashboard - Network Intrusion Detection")
print("=" * 50)
print()
print("Features:")
print("  - Real-time packet capture")
print("  - Rule-based detection")
print("  - PCAP upload/save")
print("  - Web-based interface")
print()
print("=" * 50)
print()

from nids_server import app, init_app

init_app()

port = int(os.environ.get('PORT', 5001))

print()
print("Dashboard is ready!")
print()
print("To view the interface:")
print("  1. Open a web browser")
print(f"  2. Go to: http://localhost:{port}")
print()
print("Press Ctrl+C to stop the server")
print("=" * 50)
print()

# Run Flask
app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

