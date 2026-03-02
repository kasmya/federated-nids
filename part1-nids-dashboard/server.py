"""
NIDS Dashboard - Simple Python HTTP Server
No frameworks - just Python's built-in http.server
"""

import http.server
import socketserver
import json
import os
import socket
import ipaddress
from datetime import datetime
from collections import defaultdict
import threading

PORT = 5000
DIRECTORY = "web"

# Thread-safe capture state
class CaptureState:
    def __init__(self):
        self._lock = threading.RLock()
        self.running = False
        self.interface = None
        self.packet_count = 0
        self.alert_count = 0
        self.start_time = None
        self.alerts = []
        
state = CaptureState()

# Load rules
rules = []
try:
    with open('rules.txt', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and line.startswith('alert'):
                rules.append(line)
except:
    rules = ["alert tcp any any --> any 22 SSH_DETECTED"]

def proto_name(proto_num):
    for name, num in socket.ipproto.items():
        if name.startswith("ipproto") and proto_num == num:
            return name[8:]
    return "tcp"

def check_rules(src, dst, proto, sport, dport):
    for rule in rules:
        parts = rule.split()
        if len(parts) < 7:
            continue
        # alert [proto] [srcip] [srcport] --> [dstip] [dstport] [msg]
        rule_proto = parts[1].lower()
        rule_src = parts[2].lower()
        rule_sport = parts[3]
        rule_dst = parts[5].lower()
        rule_dport = parts[6]
        msg = ' '.join(parts[7:]) if len(parts) > 7 else 'Alert'
        
        match = True
        if rule_proto != 'any' and rule_proto != proto:
            match = False
        if match and rule_src != 'any':
            if '/' in rule_src:
                try:
                    if ipaddress.IPv4Address(src) not in ipaddress.IPv4Network(rule_src):
                        match = False
                except:
                    match = False
            elif src != rule_src:
                match = False
        if match and rule_dst != 'any':
            if '/' in rule_dst:
                try:
                    if ipaddress.IPv4Address(dst) not in ipaddress.IPv4Network(rule_dst):
                        match = False
                except:
                    match = False
            elif dst != rule_dst:
                match = False
        if match and rule_sport != 'any' and str(sport) != rule_sport:
            match = False
        if match and rule_dport != 'any' and str(dport) != rule_dport:
            match = False
        if match:
            return msg
    return None

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def do_POST(self):
        if self.path == '/api/capture':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            if data.get('action') == 'start':
                state.running = True
                state.interface = data.get('interface')
                state.start_time = datetime.now()
                state.packet_count = 0
                state.alert_count = 0
                state.alerts = []
            elif data.get('action') == 'stop':
                state.running = False
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_GET(self):
        if self.path == '/api/status':
            elapsed = (datetime.now() - state.start_time).total_seconds() if state.start_time else 0
            data = {
                'running': state.running,
                'packet_count': state.packet_count,
                'alert_count': state.alert_count,
                'elapsed': elapsed
            }
            self.send_json(data)
        elif self.path == '/api/alerts':
            self.send_json({'alerts': state.alerts})
        elif self.path == '/api/interfaces':
            # Get interfaces
            ifaces = []
            try:
                import subprocess
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                current = None
                for line in result.stdout.split('\n'):
                    if line.startswith('en') and ':' in line:
                        current = line.split(':')[0].strip()
                    elif 'inet ' in line and current:
                        ip = line.split()[1]
                        ifaces.append({'name': current, 'ip': ip})
                        current = None
            except:
                ifaces = [{'name': 'en0', 'ip': 'auto'}, {'name': 'lo', 'ip': '127.0.0.1'}]
            self.send_json({'interfaces': ifaces})
        elif self.path == '/api/rules':
            self.send_json({'rules': rules})
        else:
            super().do_GET()
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def log_message(self, format, *args):
        pass  # Suppress logging

print(f"NIDS Dashboard starting on http://localhost:{PORT}")
print("Press Ctrl+C to stop")

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()

