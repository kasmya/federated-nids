#!/usr/bin/env python3
"""
NIDS Web Dashboard - Simple Server (No WebSocket)
This version uses basic Flask polling instead of WebSocket
"""

import os
import sys
import json
import threading
import logging
import socket
import ipaddress
import codecs
import glob
import subprocess
import re
from datetime import datetime
from collections import defaultdict

from flask import Flask, render_template, request, jsonify, send_file

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, 
            static_folder='static',
            static_url_path='/static',
            template_folder='templates')

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, 'temp')
PCAP_DIR = os.path.join(BASE_DIR, 'saved_pcap')
YARA_RULES_DIR = os.path.join(BASE_DIR, 'yara_rules')
TCPFLOW_DIR = os.path.join(BASE_DIR, 'temp', 'tcpflowdump')

for d in [TEMP_DIR, PCAP_DIR, YARA_RULES_DIR, TCPFLOW_DIR]:
    os.makedirs(d, exist_ok=True)

SSL_LOG_FILE = os.path.join(TEMP_DIR, 'ssl.log')
YARA_RULES_FILE = os.path.join(YARA_RULES_DIR, 'rules1.yara')

# Thread-safe capture state
class CaptureState:
    def __init__(self):
        self._lock = threading.RLock()
        self.reset()
    
    def reset(self):
        with self._lock:
            self.running = False
            self.interface = None
            self.packet_count = 0
            self.alert_count = 0
            self.start_time = None
            self.pkt_list = []
            self.suspicious_packets = []
            self.sus_readable_payloads = []
            self.tcp_streams = []
            self.http2_streams = []
            self.protocol_stats = defaultdict(int)
    
    def add_packet(self, pkt):
        with self._lock:
            self.pkt_list.append(pkt)
            self.packet_count += 1
    
    def add_alert(self, alert, payload):
        with self._lock:
            self.alert_count += 1
            self.suspicious_packets.append(alert)
            self.sus_readable_payloads.append(payload)
    
    def get_summary(self):
        with self._lock:
            elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            return {
                'running': self.running,
                'interface': self.interface,
                'packet_count': self.packet_count,
                'alert_count': self.alert_count,
                'tcp_streams': len(self.tcp_streams),
                'http2_streams': len(self.http2_streams),
                'elapsed': elapsed
            }
    
    def get_alerts(self):
        with self._lock:
            return list(self.suspicious_packets[-100:])

capture_state = CaptureState()

# Rules state
rules_state = {'protocols': [], 'src_ips': [], 'src_ports': [], 'dst_ips': [], 'dst_ports': [], 'messages': [], 'raw_rules': []}

def proto_name_by_num(proto_num):
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:].lower()
    return "unknown"

def get_interfaces():
    interfaces = []
    try:
        from scapy.arch import get_if_list
        for iface_name in get_if_list():
            iface_info = {'name': iface_name, 'ip': 'N/A'}
            try:
                iface_ip = scapy.get_if_addr(iface_name)
                if iface_ip:
                    iface_info['ip'] = str(iface_ip)
            except:
                pass
            interfaces.append(iface_info)
    except:
        interfaces = [{'name': 'en0', 'ip': 'Auto-detect'}, {'name': 'lo', 'ip': '127.0.0.1'}]
    return interfaces

def load_network_rules(rule_file="rules.txt"):
    global rules_state
    rules_state = {'protocols': [], 'src_ips': [], 'src_ports': [], 'dst_ips': [], 'dst_ports': [], 'messages': [], 'raw_rules': []}
    
    try:
        with open(rule_file, 'r') as f:
            for rule in f.readlines():
                rule = rule.strip()
                if not rule or rule.startswith('#') or not rule.startswith('alert'):
                    continue
                rules_state['raw_rules'].append(rule)
                parts = rule.split()
                if len(parts) < 7:
                    continue
                rules_state['protocols'].append(parts[1].lower() if parts[1] != 'any' else 'any')
                rules_state['src_ips'].append(parts[2].lower() if parts[2] != 'any' else 'any')
                rules_state['src_ports'].append(parts[3] if parts[3] != 'any' else 'any')
                rules_state['dst_ips'].append(parts[5].lower() if parts[5] != 'any' else 'any')
                rules_state['dst_ports'].append(parts[6] if parts[6] != 'any' else 'any')
                rules_state['messages'].append(' '.join(parts[7:]) if len(parts) > 7 else 'No message')
        logger.info(f"Loaded {len(rules_state['raw_rules'])} rules")
    except Exception as e:
        logger.error(f"Error loading rules: {e}")

def check_packet_rules(pkt):
    if 'IP' not in pkt:
        return None
    try:
        src, dst, proto = pkt['IP'].src, pkt['IP'].dst, proto_name_by_num(pkt['IP'].proto)
        sport, dport = getattr(pkt['IP'], 'sport', 0), getattr(pkt['IP'].dport', 0)
    except:
        return None
    
    for i in range(len(rules_state['protocols'])):
        match = True
        if rules_state['protocols'][i] != 'any' and rules_state['protocols'][i] != proto:
            match = False
        if match:
            rule_src = rules_state['src_ips'][i]
            if rule_src != 'any':
                if '/' in rule_src:
                    try:
                        if ipaddress.IPv4Address(src) not in ipaddress.IPv4Network(rule_src):
                            match = False
                    except:
                        match = False
                elif src != rule_src:
                    match = False
        if match:
            rule_dst = rules_state['dst_ips'][i]
            if rule_dst != 'any':
                if '/' in rule_dst:
                    try:
                        if ipaddress.IPv4Address(dst) not in ipaddress.IPv4Network(rule_dst):
                            match = False
                    except:
                        match = False
                elif dst != rule_dst:
                    match = False
        if match:
            rule_sport = rules_state['src_ports'][i]
            if rule_sport != 'any' and str(sport) != str(rule_sport):
                match = False
        if match:
            rule_dport = rules_state['dst_ports'][i]
            if rule_dport != 'any' and str(dport) != str(rule_dport):
                match = False
        if match:
            return {'message': rules_state['messages'][i], 'src': src, 'dst': dst, 'proto': proto, 'sport': sport, 'dport': dport}
    return None

def process_packet(pkt):
    if not capture_state.running:
        return
    capture_state.add_packet(pkt)
    if 'IP' in pkt:
        proto = proto_name_by_num(pkt['IP'].proto)
        with capture_state._lock:
            capture_state.protocol_stats[proto] += 1
    rule_match = check_packet_rules(pkt)
    if rule_match:
        payload = ""
        if 'TCP' in pkt:
            try:
                payload = bytes(pkt['TCP'].payload).decode('utf-8', 'replace')
            except:
                payload = "<binary>"
        elif 'UDP' in pkt:
            try:
                payload = bytes(pkt['UDP'].payload).decode('utf-8', 'replace')
            except:
                payload = "<binary>"
        alert = {
            'id': capture_state.alert_count + 1,
            'timestamp': datetime.now().isoformat(),
            'message': rule_match['message'],
            'src': rule_match['src'],
            'dst': rule_match['dst'],
            'proto': rule_match['proto'],
            'sport': rule_match['sport'],
            'dport': rule_match['dport'],
            'payload': payload[:500]
        }
        capture_state.add_alert(alert, payload)

def start_capture(interface):
    if capture_state.running:
        return
    capture_state.reset()
    capture_state.running = True
    capture_state.interface = interface
    capture_state.start_time = datetime.now()
    
    import scapy.all as scapy
    
    def capture_thread():
        try:
            logger.info(f"Starting capture on {interface}")
            scapy.sniff(prn=process_packet, store=0, iface=interface, stop_filter=lambda x: not capture_state.running)
        except Exception as e:
            logger.error(f"Capture error: {e}")
        capture_state.running = False
        logger.info("Capture stopped")
    
    thread = threading.Thread(target=capture_thread, daemon=True)
    thread.start()

def stop_capture():
    capture_state.running = False

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/interfaces')
def api_interfaces():
    return jsonify({'interfaces': get_interfaces()})

@app.route('/api/rules')
def api_rules():
    return jsonify({'rules': rules_state['raw_rules']})

@app.route('/api/capture', methods=['POST'])
def api_capture():
    data = request.json
    action = data.get('action')
    if action == 'start':
        start_capture(data.get('interface'))
        return jsonify({'status': 'started'})
    elif action == 'stop':
        stop_capture()
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'unknown'})

@app.route('/api/status')
def api_status():
    return jsonify(capture_state.get_summary())

@app.route('/api/alerts')
def api_alerts():
    return jsonify({'alerts': capture_state.get_alerts()})

@app.route('/api/upload_pcap', methods=['POST'])
def api_upload_pcap():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file'})
    file = request.files['file']
    filepath = os.path.join(TEMP_DIR, 'uploaded.pcap')
    file.save(filepath)
    try:
        import scapy.all as scapy
        cap = scapy.rdpcap(filepath)
        for pkt in cap:
            process_packet(pkt)
        return jsonify({'status': 'success', 'packets': capture_state.packet_count, 'alerts': capture_state.alert_count})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/save_pcap', methods=['POST'])
def api_save_pcap():
    filename = request.json.get('filename', f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
    filepath = os.path.join(PCAP_DIR, filename)
    try:
        with capture_state._lock:
            pkt_list = list(capture_state.pkt_list)
        if pkt_list:
            import scapy.all as scapy
            scapy.wrpcap(filepath, pkt_list)
            return jsonify({'status': 'success', 'filename': filename})
        return jsonify({'status': 'error', 'message': 'No packets'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def init_app():
    load_network_rules()
    logger.info(f"Interfaces: {len(get_interfaces())}")
    logger.info(f"Rules loaded: {len(rules_state['raw_rules'])}")

if __name__ == '__main__':
    init_app()
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting NIDS Dashboard on http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

