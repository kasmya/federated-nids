#!/usr/bin/env python3
"""
NIDS Web Dashboard - Fully Self-Contained Server
With Closed-Loop NIDS Integration (Layer 2: Brain, Layer 3: Teacher)
"""

import os
import sys
import json
import threading
import logging
import socket
import ipaddress
import random
from datetime import datetime
from collections import defaultdict

# Flask only - no scapy at module level
from flask import Flask, render_template, request, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import Closed-Loop NIDS modules
try:
    from closed_loop import (
        SimpleAnomalyDetector, 
        RuleGenerator, 
        ClosedLoopNIDS,
        get_learning_db
    )
    from closed_loop_integration import integrate_with_server
    CLOSED_LOOP_AVAILABLE = True
    logger.info("Closed-Loop NIDS modules loaded successfully")
except ImportError as e:
    CLOSED_LOOP_AVAILABLE = False
    logger.warning(f"Closed-Loop NIDS modules not available: {e}")

# YARA import
try:
    import yara
    YARA_AVAILABLE = True
    YARA_RULES = None
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA not installed - pip install yara-python")

app = Flask(__name__,
            static_folder='static',
            static_url_path='/static',
            template_folder='templates')

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP_DIR = os.path.join(BASE_DIR, 'temp')
PCAP_DIR = os.path.join(BASE_DIR, 'saved_pcap')

for d in [TEMP_DIR, PCAP_DIR]:
    os.makedirs(d, exist_ok=True)

# Load YARA rules after BASE_DIR is defined
YARA_RULES_PATH = os.path.join(BASE_DIR, 'yara_rules')
YARA_RULES = None

def load_yara_rules():
    global YARA_RULES
    if not YARA_AVAILABLE:
        return
    try:
        if os.path.exists(YARA_RULES_PATH):
            # Compile all .yar files in the directory
            rule_files = []
            for f in os.listdir(YARA_RULES_PATH):
                if f.endswith('.yar') or f.endswith('.yara'):
                    rule_files.append(os.path.join(YARA_RULES_PATH, f))
            
            if rule_files:
                YARA_RULES = yara.compile(filepaths={f'rule_{i}': f for i, f in enumerate(rule_files)})
                logger.info(f"Loaded {len(rule_files)} YARA rule files")
            else:
                logger.info("No YARA rules found")
        else:
            logger.info("YARA rules directory not found")
    except Exception as e:
        logger.warning(f"YARA rules loading failed: {e}")
        YARA_RULES = None

# Load YARA rules
if YARA_AVAILABLE:
    load_yara_rules()

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
            self.protocol_stats = defaultdict(int)
            self.yara_matches = []  # Store YARA scan results
    
    def add_packet(self, pkt):
        with self._lock:
            self.pkt_list.append(pkt)
            self.packet_count += 1
    
    def add_alert(self, alert, payload):
        with self._lock:
            self.alert_count += 1
            self.suspicious_packets.append(alert)
            self.sus_readable_payloads.append(payload)
    
    def add_yara_match(self, match):
        with self._lock:
            self.yara_matches.append(match)
            # Keep only last 50 matches
            if len(self.yara_matches) > 50:
                self.yara_matches = self.yara_matches[-50:]
    
    def get_summary(self):
        with self._lock:
            elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            return {
                'running': self.running,
                'interface': self.interface,
                'packet_count': self.packet_count,
                'alert_count': self.alert_count,
                'elapsed': elapsed
            }
    
    def get_alerts(self):
        with self._lock:
            return list(self.suspicious_packets[-100:])
    
    def get_yara_matches(self):
        with self._lock:
            return list(self.yara_matches)

capture_state = CaptureState()

# Closed-Loop NIDS Components
closed_loop_nids = None
anomaly_detector = None
rule_generator = None
learning_db = None

# Initialize Closed-Loop NIDS if available
def init_closed_loop():
    global closed_loop_nids, anomaly_detector, rule_generator, learning_db
    
    if not CLOSED_LOOP_AVAILABLE:
        logger.warning("Closed-Loop NIDS not available - running in basic mode")
        return False
    
    try:
        # Initialize components
        config = {
            'window_size': 10,
            'detection_threshold': 0.2,  # Lower threshold for easier detection
            'auto_rules_file': 'auto_rules.txt',
            'db_path': 'learning.db',
            'auto_generate_rules': True
        }
        
        closed_loop_nids = ClosedLoopNIDS(config)
        anomaly_detector = closed_loop_nids.detector
        rule_generator = closed_loop_nids.rule_generator
        learning_db = get_learning_db()
        
        logger.info("Closed-Loop NIDS initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize Closed-Loop NIDS: {e}")
        return False

# Initialize on module load
init_closed_loop()

# Rules state
rules_state = {'protocols': [], 'src_ips': [], 'src_ports': [], 'dst_ips': [], 'dst_ports': [], 'messages': [], 'raw_rules': []}

# Lazy scapy import
def get_scapy():
    import scapy.all as scapy
    return scapy

def proto_name_by_num(proto_num):
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:].lower()
    return "unknown"

def get_interfaces():
    interfaces = []
    try:
        scapy = get_scapy()
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
        sport, dport = getattr(pkt['IP'], 'sport', 0), getattr(pkt['IP'], 'dport', 0)
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
    
    # Convert packet to dict for anomaly detection
    pkt_dict = None
    if 'IP' in pkt:
        proto = proto_name_by_num(pkt['IP'].proto)
        with capture_state._lock:
            capture_state.protocol_stats[proto] += 1
        
        # Create packet dict for anomaly detector
        pkt_dict = {
            'src': pkt['IP'].src,
            'dst': pkt['IP'].dst,
            'proto': proto,
            'sport': getattr(pkt['IP'], 'sport', 0),
            'dport': getattr(pkt['IP'], 'dport', 0),
            'length': len(pkt)
        }
        
        # Add TCP flags if available
        if 'TCP' in pkt:
            pkt_dict['flags'] = str(pkt['TCP'].flags) if hasattr(pkt['TCP'], 'flags') else ''
    
    # Process through anomaly detector if available
    if anomaly_detector and pkt_dict:
        try:
            anomaly = anomaly_detector.process_packet(pkt_dict)
            if anomaly:
                # Add anomaly as an alert
                logger.info(f"Anomaly detected: {anomaly.anomaly_type} from {anomaly.src_ip} (score: {anomaly.score})")
                alert = {
                    'id': capture_state.alert_count + 1,
                    'timestamp': anomaly.timestamp.isoformat(),
                    'message': f"[ANOMALY] {anomaly.anomaly_type.upper()} - Score: {anomaly.score:.2f}",
                    'src': anomaly.src_ip,
                    'dst': pkt_dict.get('dst', 'N/A'),
                    'proto': pkt_dict.get('proto', 'N/A'),
                    'sport': 0,
                    'dport': pkt_dict.get('dport', 0),
                    'payload': f"Anomaly Details: {anomaly.details.get('description', 'N/A')}",
                    'anomaly_type': anomaly.anomaly_type,
                    'anomaly_score': anomaly.score
                }
                capture_state.add_alert(alert, alert['payload'])
        except Exception as e:
            logger.error(f"Error processing anomaly: {e}")
    
    # Check for rule-based detection
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
    
    # Try real capture first, fall back to simulation
    try:
        scapy = get_scapy()
        
        def capture_thread():
            try:
                logger.info(f"Starting capture on {interface}")
                scapy.sniff(prn=process_packet, store=0, iface=interface, stop_filter=lambda x: not capture_state.running)
            except Exception as e:
                logger.warning(f"Real capture failed: {e}, starting simulation mode")
                # Don't stop yet - simulation will handle it
                if capture_state.running:
                    start_simulation()
                return
            capture_state.running = False
            logger.info("Capture stopped")
        
        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
    except Exception as e:
        logger.warning(f"Could not initialize scapy: {e}, starting simulation mode")
        start_simulation()

def start_simulation():
    """Generate simulated network traffic for demo purposes"""
    logger.info("Starting traffic simulation mode")
    
    # Sample data for simulation
    protocols = ['tcp', 'udp', 'icmp']
    ports = [80, 443, 22, 53, 8080, 3000, 21, 25, 110, 143]
    ips = ['192.168.1.' + str(i) for i in range(1, 50)]
    external_ips = ['8.8.8.8', '1.1.1.1', '142.250.80.46', '151.101.1.140']
    messages = ['SSH_DETECTED', 'SUSPICIOUS_DNS', 'HTTP_TRAFFIC', 'INTERNAL_SCAN', 'FTP_CONNECTION']
    
    # Track scan simulation state
    scan_counter = 0
    scan_mode = False
    scan_src_ip = None
    
    def simulate_traffic():
        nonlocal scan_counter, scan_mode, scan_src_ip
        
        # Track packets per scan for this simulation session
        packets_in_current_scan = 0
        ports_scanned = set()
        
        while capture_state.running:
            try:
                # Every 20 packets, trigger a port scan to generate anomalies
                scan_counter += 1
                
                if scan_counter > 20 and not scan_mode:
                    # Start a simulated port scan
                    scan_mode = True
                    scan_src_ip = random.choice(ips)
                    packets_in_current_scan = 0
                    ports_scanned = set()
                    scan_counter = 0
                    logger.info(f"[SIM] Starting port scan simulation from {scan_src_ip}")
                
                # Generate random packet data
                proto = random.choice(protocols)
                
                # In scan mode, generate packets to many different ports from same IP
                if scan_mode and scan_src_ip:
                    src_ip = scan_src_ip
                    # Scan multiple destination IPs with different ports
                    dst_ip = random.choice(external_ips)
                    dport = random.randint(1, 100)  # Scan many ports
                    ports_scanned.add(dport)
                    packets_in_current_scan += 1
                    
                    if proto == 'tcp':
                        pkt_flags = 'S'  # SYN scan
                    else:
                        pkt_flags = ''
                    
                    # End scan mode after scanning enough ports (at least 20)
                    if len(ports_scanned) >= 20:
                        scan_mode = False
                        logger.info(f"[SIM] Port scan simulation ended - scanned {len(ports_scanned)} ports")
                else:
                    # Normal traffic
                    src_ip = random.choice(ips)
                    dst_ip = random.choice(external_ips) if random.random() > 0.3 else random.choice(ips)
                    dport = random.choice(ports)
                    pkt_flags = random.choice(['S', 'A', 'PA', 'SA', 'F', 'R']) if proto == 'tcp' else ''
                
                sport = random.randint(49152, 65535)
                
                # Create simulated packet-like data
                pkt_data = {
                    'src': src_ip,
                    'dst': dst_ip,
                    'proto': proto,
                    'sport': sport,
                    'dport': dport,
                    'summary': f"{proto.upper()} {src_ip}:{sport} -> {dst_ip}:{dport}",
                    'length': random.randint(64, 1500),
                    'flags': pkt_flags
                }
                
                # Add to packet count
                with capture_state._lock:
                    capture_state.packet_count += 1
                    capture_state.protocol_stats[proto] += 1
                    # Store simplified packet for display
                    capture_state.pkt_list.append(pkt_data)
                
                # Process through anomaly detector if available
                if anomaly_detector:
                    try:
                        anomaly = anomaly_detector.process_packet(pkt_data)
                        if anomaly:
                            # Add anomaly as an alert
                            logger.info(f"[SIM] Anomaly detected: {anomaly.anomaly_type} from {anomaly.src_ip}")
                            alert = {
                                'id': capture_state.alert_count + 1,
                                'timestamp': anomaly.timestamp.isoformat(),
                                'message': f"[ANOMALY] {anomaly.anomaly_type.upper()} - Score: {anomaly.score:.2f}",
                                'src': anomaly.src_ip,
                                'dst': dst_ip,
                                'proto': proto,
                                'sport': 0,
                                'dport': dport,
                                'payload': f"Anomaly Details: {anomaly.details.get('description', 'N/A')}",
                                'anomaly_type': anomaly.anomaly_type,
                                'anomaly_score': anomaly.score
                            }
                            capture_state.add_alert(alert, alert['payload'])
                    except Exception as e:
                        logger.error(f"Error in anomaly detection: {e}")
                
                # Check for rule matches and generate alerts
                for i in range(len(rules_state['protocols'])):
                    rule_proto = rules_state['protocols'][i]
                    rule_msg = rules_state['messages'][i]
                    
                    if rule_proto == 'any' or rule_proto == proto:
                        # Randomly generate alerts based on rules
                        if random.random() < 0.01:  # 10% chance of alert
                            # Generate simulated payload for YARA scanning
                            payloads = [
                                "GET /admin.php?id=1' OR '1'='1 HTTP/1.1",  # SQL Injection
                                "<script>alert('XSS')</script>",  # XSS
                                "GET /etc/passwd HTTP/1.1",  # Path traversal
                                "POST /cgi-bin/bash HTTP/1.1\n/bin/sh -i",  # Shellshock
                                "GET /search?q=UNION ALL SELECT password FROM users",  # SQL Injection
                                "GET /api?cmd=whoami HTTP/1.1",  # Command injection
                                "GET /download?file=../../etc/passwd",  # LFI
                                "normal HTTP request data here",  # Normal
                            ]
                            payload = random.choice(payloads)
                            
                            alert = {
                                'id': capture_state.alert_count + 1,
                                'timestamp': datetime.now().isoformat(),
                                'message': rule_msg,
                                'src': src_ip,
                                'dst': dst_ip,
                                'proto': proto,
                                'sport': sport,
                                'dport': dport,
                                'payload': payload
                            }
                            capture_state.add_alert(alert, payload)
                            
                            # Scan payload with YARA
                            if YARA_AVAILABLE and YARA_RULES:
                                try:
                                    matches = scan_payload_yara(payload, src_ip, dst_ip, proto)
                                    for match in matches:
                                        capture_state.add_yara_match(match)
                                        # Add YARA match as alert
                                        alert['id'] = capture_state.alert_count + 1
                                        alert['message'] = f"[YARA] {match['rule']} - {match['meta'].get('description', 'Malware detected')}"
                                        alert['payload'] = f"YARA Match: {match['rule']} | Tags: {', '.join(match['tags']) if match['tags'] else 'None'}"
                                        capture_state.add_alert(alert, payload)
                                        logger.info(f"[YARA] Match found: {match['rule']} from {src_ip}")
                                except Exception as e:
                                    logger.debug(f"YARA scan error: {e}")
                            
                            break
                
                # Sleep for random interval
                time.sleep(random.uniform(0.1, 0.5))
                
            except Exception as e:
                logger.error(f"Simulation error: {e}")
                break
        
        logger.info("Simulation stopped")
    
    import time
    sim_thread = threading.Thread(target=simulate_traffic)
    sim_thread.start()

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

@app.route('/api/protocols')
def api_protocols():
    with capture_state._lock:
        return jsonify({'stats': dict(capture_state.protocol_stats)})

@app.route('/api/packets')
def api_packets():
    """Get captured packets for display"""
    with capture_state._lock:
        packets = []
        for pkt in capture_state.pkt_list[-100:]:
            # Handle both real scapy packets and simulated dicts
            if hasattr(pkt, 'src'):  # Real scapy packet
                packets.append({
                    'src': pkt.get('src', 'N/A'),
                    'dst': pkt.get('dst', 'N/A'),
                    'proto': proto_name_by_num(pkt.get('proto', 0)) if hasattr(pkt, 'proto') else 'N/A',
                    'sport': getattr(pkt, 'sport', 0),
                    'dport': getattr(pkt, 'dport', 0),
                    'summary': str(pkt.summary()) if hasattr(pkt, 'summary') else 'N/A'
                })
            else:  # Simulated dict
                packets.append(pkt)
        return jsonify({'packets': packets})

@app.route('/api/upload_pcap', methods=['POST'])
def api_upload_pcap():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file'})
    file = request.files['file']
    filepath = os.path.join(TEMP_DIR, 'uploaded.pcap')
    file.save(filepath)
    try:
        scapy = get_scapy()
        cap = scapy.rdpcap(filepath)
        for pkt in cap:
            process_packet(pkt)
        return jsonify({'status': 'success', 'packets': capture_state.packet_count, 'alerts': capture_state.alert_count})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/save_pcap', methods=['POST'])
def api_save_pcap():
    """Save captured packets to PCAP file"""
    filename = request.json.get('filename', f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
    filepath = os.path.join(PCAP_DIR, filename)
    try:
        with capture_state._lock:
            pkt_list = list(capture_state.pkt_list)
        
        if not pkt_list:
            return jsonify({'status': 'error', 'message': 'No packets captured'})
        
        # Filter only real scapy packets (not simulated dicts)
        scapy = get_scapy()
        real_packets = []
        simulated_count = 0
        
        for pkt in pkt_list:
            # Check if it's a scapy packet (has layers method) or a dict (simulated)
            if hasattr(pkt, 'layers'):  # Real scapy packet
                real_packets.append(pkt)
            else:
                simulated_count += 1
        
        if real_packets:
            scapy.wrpcap(filepath, real_packets)
            return jsonify({'status': 'success', 'filename': filename, 'message': f'Saved {len(real_packets)} real packets'})
        else:
            # For simulated packets, save as JSON instead
            json_filename = filename.replace('.pcap', '.json')
            json_filepath = os.path.join(PCAP_DIR, json_filename)
            import json
            with open(json_filepath, 'w') as f:
                json.dump({
                    'packets': pkt_list,
                    'capture_time': datetime.now().isoformat(),
                    'note': 'Simulated packets - not in PCAP format'
                }, f, indent=2)
            return jsonify({'status': 'success', 'filename': json_filename, 'message': f'Saved {len(pkt_list)} simulated packets as JSON (PCAP not available for simulated data)'})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# YARA scanning functions
def scan_payload_yara(payload_data, src_ip='', dst_ip='', proto=''):
    """Scan payload data using YARA rules"""
    if not YARA_AVAILABLE or YARA_RULES is None:
        return []
    
    matches = []
    try:
        # Convert payload to bytes if string
        if isinstance(payload_data, str):
            data = payload_data.encode('utf-8', errors='ignore')
        else:
            data = payload_data
        
        # Scan with YARA
        yara_matches = YARA_RULES.match(data=data)
        
        for match in yara_matches:
            matches.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': dict(match.meta) if match.meta else {},
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'proto': proto,
                'timestamp': datetime.now().isoformat()
            })
    except Exception as e:
        logger.debug(f"YARA scan error: {e}")
    
    return matches

@app.route('/api/yara/scan', methods=['POST'])
def api_yara_scan():
    """Manual YARA scan endpoint"""
    if not YARA_AVAILABLE:
        return jsonify({'status': 'error', 'message': 'YARA not available'})
    
    data = request.json
    payload = data.get('payload', '')
    src_ip = data.get('src_ip', '')
    dst_ip = data.get('dst_ip', '')
    proto = data.get('proto', '')
    
    matches = scan_payload_yara(payload, src_ip, dst_ip, proto)
    return jsonify({'matches': matches, 'count': len(matches)})

@app.route('/api/yara/status')
def api_yara_status():
    """Get YARA engine status"""
    return jsonify({
        'available': YARA_AVAILABLE,
        'rules_loaded': YARA_RULES is not None,
        'matches': capture_state.get_yara_matches()
    })

def init_app():
    load_network_rules()
    
    # Integrate closed-loop NIDS if available
    if CLOSED_LOOP_AVAILABLE and closed_loop_nids:
        integrate_with_server(app, capture_state, rules_state, closed_loop_nids)
        logger.info("Closed-Loop NIDS integration complete")
    
    logger.info(f"NIDS Dashboard initialized")
    logger.info(f"Interfaces available: {len(get_interfaces())}")
    logger.info(f"Rules loaded: {len(rules_state['raw_rules'])}")


@app.route('/api/export/json', methods=['POST'])
def api_export_json():
    """Export captured data as JSON (works for both real and simulated packets)"""
    try:
        with capture_state._lock:
            packets = list(capture_state.pkt_list)
            alerts = list(capture_state.suspicious_packets)
            yara_matches = list(capture_state.yara_matches)
        
        export_data = {
            'export_time': datetime.now().isoformat(),
            'packet_count': len(packets),
            'alert_count': len(alerts),
            'yara_match_count': len(yara_matches),
            'packets': packets,
            'alerts': alerts,
            'yara_matches': yara_matches,
            'protocol_stats': dict(capture_state.protocol_stats)
        }
        
        return jsonify({'status': 'success', 'data': export_data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    init_app()
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting NIDS Dashboard on http://localhost:{port}")
    logger.info("Press Ctrl+C to stop")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
