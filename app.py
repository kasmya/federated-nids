"""
NIDS Web Dashboard - Network Intrusion Detection System
Flask backend with SocketIO for real-time updates

Features:
- Real-time packet capture and analysis
- WebSocket-based live updates
- Rule-based detection with CIDR support
- TCP/HTTP stream extraction
- YARA malware scanning
- Cross-platform (macOS, Linux, Windows)
"""

import os
import sys
import json
import time
import threading
import logging
import socket
import ipaddress
import codecs
import glob
import subprocess
import re
from datetime import datetime
from functools import wraps
from collections import defaultdict

from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from flask_socketio import SocketIO, emit

import scapy.all as scapy
import pyshark

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('nids.log')
    ]
)
logger = logging.getLogger(__name__)

# ============== CONFIGURATION ==============
app = Flask(__name__, 
            static_folder='static',
            static_url_path='/static',
            template_folder='templates')

app.config['SECRET_KEY'] = 'nids_secret_key_change_in_production'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload

# SocketIO with eventlet for production, fallback to threading for development
try:
    import eventlet
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
    logger.info("Using eventlet async mode")
except ImportError:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    logger.warning("eventlet not found, using threading mode")

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
TEMP_DIR = os.path.join(BASE_DIR, 'temp')
PCAP_DIR = os.path.join(BASE_DIR, 'saved_pcap')
YARA_RULES_DIR = os.path.join(BASE_DIR, 'yara_rules')
TCPFLOW_DIR = os.path.join(BASE_DIR, 'temp', 'tcpflowdump')

# Create directories if they don't exist
for d in [TEMP_DIR, PCAP_DIR, YARA_RULES_DIR, TCPFLOW_DIR]:
    os.makedirs(d, exist_ok=True)

# SSL keylog for PyShark TLS decryption
SSL_LOG_FILE = os.path.join(TEMP_DIR, 'ssl.log')
YARA_RULES_FILE = os.path.join(YARA_RULES_DIR, 'rules1.yara')

# ============== GLOBAL STATE ==============
class CaptureState:
    """Thread-safe capture state management"""
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
            self.all_readable_payloads = []
            self.tcp_streams = []
            self.http2_streams = []
            self.http_objects = []
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
            return {
                'running': self.running,
                'interface': self.interface,
                'packet_count': self.packet_count,
                'alert_count': self.alert_count,
                'tcp_streams': len(self.tcp_streams),
                'http2_streams': len(self.http2_streams),
                'elapsed': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            }

capture_state = CaptureState()

# Rules state
rules_state = {
    'protocols': [],
    'src_ips': [],
    'src_ports': [],
    'dst_ips': [],
    'dst_ports': [],
    'messages': [],
    'raw_rules': []
}

# ============== HELPER FUNCTIONS ==============
def proto_name_by_num(proto_num):
    """Convert protocol number to name"""
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:].lower()
    return "unknown"

def get_interfaces():
    """Get available network interfaces - cross-platform"""
    interfaces = []
    
    try:
        # Method 1: Try scapy's get_if_list (works on most platforms)
        from scapy.arch import get_if_list
        for iface_name in get_if_list():
            iface_info = {
                'name': iface_name,
                'ip': 'N/A',
                'mac': 'N/A', 
                'description': ''
            }
            try:
                # Get IP address for interface
                iface_ip = scapy.get_if_addr(iface_name)
                if iface_ip:
                    iface_info['ip'] = str(iface_ip)
            except:
                pass
            interfaces.append(iface_info)
        
        # Method 2: On Windows, try Windows-specific
        if sys.platform == 'win32' and not interfaces:
            try:
                import scapy.arch.windows as win_arch
                for iface in win_arch.get_windows_if_list():
                    interfaces.append({
                        'name': iface.get('name', 'Unknown'),
                        'ip': iface.get('ip', 'N/A'),
                        'mac': iface.get('mac', 'N/A'),
                        'description': iface.get('description', '')
                    })
            except Exception as e:
                logger.warning(f"Windows interface detection failed: {e}")
        
        # Method 3: Use ipconfig/ifconfig as fallback
        if not interfaces:
            try:
                if sys.platform == 'darwin':  # macOS
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                    current_iface = None
                    for line in result.stdout.split('\n'):
                        if line.startswith('en'):
                            current_iface = line.split(':')[0].strip()
                        elif 'inet ' in line and current_iface:
                            ip = line.split()[1]
                            interfaces.append({
                                'name': current_iface,
                                'ip': ip,
                                'mac': 'N/A',
                                'description': ''
                            })
                            current_iface = None
            except Exception as e:
                logger.warning(f"ifconfig fallback failed: {e}")
    
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
    
    # Add fallback interfaces if none detected
    if not interfaces:
        interfaces = [
            {'name': 'eth0', 'ip': 'Auto-detect', 'mac': 'N/A', 'description': 'Primary interface'},
            {'name': 'lo', 'ip': '127.0.0.1', 'mac': 'N/A', 'description': 'Loopback'}
        ]
    
    return interfaces

# ============== RULE PROCESSING ==============
def load_network_rules(rule_file="rules.txt"):
    """Load and parse network detection rules"""
    global rules_state
    
    rules_state = {
        'protocols': [],
        'src_ips': [],
        'src_ports': [],
        'dst_ips': [],
        'dst_ports': [],
        'messages': [],
        'raw_rules': []
    }
    
    try:
        with open(rule_file, 'r') as f:
            rules = f.readlines()
        
        for rule in rules:
            rule = rule.strip()
            if not rule or rule.startswith('#'):
                continue
            if not rule.startswith('alert'):
                continue
            
            rules_state['raw_rules'].append(rule)
            
            parts = rule.split()
            if len(parts) < 7:
                continue
            
            # Parse rule: alert [proto] [srcip] [srcport] --> [dstip] [dstport] [msg...]
            protocols = parts[1].lower() if parts[1] != 'any' else 'any'
            src_ips = parts[2].lower() if parts[2] != 'any' else 'any'
            src_ports = parts[3] if parts[3] != 'any' else 'any'
            dst_ips = parts[5].lower() if parts[5] != 'any' else 'any'
            dst_ports = parts[6] if parts[6] != 'any' else 'any'
            msg = ' '.join(parts[7:]) if len(parts) > 7 else 'No message'
            
            rules_state['protocols'].append(protocols)
            rules_state['src_ips'].append(src_ips)
            rules_state['src_ports'].append(src_ports)
            rules_state['dst_ips'].append(dst_ips)
            rules_state['dst_ports'].append(dst_ports)
            rules_state['messages'].append(msg)
        
        logger.info(f"Loaded {len(rules_state['raw_rules'])} rules")
        socketio.emit('rules_loaded', {'rules': rules_state['raw_rules']})
        
    except FileNotFoundError:
        logger.warning(f"Rules file {rule_file} not found")
    except Exception as e:
        logger.error(f"Error loading rules: {e}")

def check_packet_rules(pkt):
    """Check if packet matches any detection rule"""
    if 'IP' not in pkt:
        return None
    
    try:
        src = pkt['IP'].src
        dst = pkt['IP'].dst
        proto = proto_name_by_num(pkt['IP'].proto)
        sport = getattr(pkt['IP'], 'sport', 0)
        dport = getattr(pkt['IP'], 'dport', 0)
    except Exception as e:
        return None
    
    for i in range(len(rules_state['protocols'])):
        match = True
        
        # Protocol check
        if rules_state['protocols'][i] != 'any' and rules_state['protocols'][i] != proto:
            match = False
        
        # Source IP check
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
        
        # Destination IP check
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
        
        # Port checks
        if match:
            rule_sport = rules_state['src_ports'][i]
            if rule_sport != 'any' and str(sport) != str(rule_sport):
                match = False
        
        if match:
            rule_dport = rules_state['dst_ports'][i]
            if rule_dport != 'any' and str(dport) != str(rule_dport):
                match = False
        
        if match:
            return {
                'message': rules_state['messages'][i],
                'src': src,
                'dst': dst,
                'proto': proto,
                'sport': sport,
                'dport': dport
            }
    
    return None

# ============== HTTP ANALYSIS ==============
def get_http_headers(http_payload):
    """Extract HTTP headers from payload"""
    try:
        headers_raw = http_payload[:http_payload.index(b"\r\n\r\n") + 2]
        headers = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
        if b"Content-Type" not in headers:
            return None
        return headers
    except:
        return None

def extract_http_object(headers, http_payload):
    """Extract HTTP object from payload"""
    try:
        obj_start = http_payload.index(b"\r\n\r\n") + 4
        obj_extracted = http_payload[obj_start:]
        obj_type = obj_extracted[:10]  # First bytes for type detection
        return obj_extracted, obj_type
    except:
        return None, None

def read_http_objects():
    """Read HTTP objects from captured packets"""
    objects = []
    try:
        temp_pcap = os.path.join(TEMP_DIR, 'httpstreamread.pcap')
        
        # Write packets to temp file
        with capture_state._lock:
            pkt_list = list(capture_state.pkt_list)
        
        if not pkt_list:
            return objects
            
        scapy.wrpcap(temp_pcap, pkt_list)
        cap = scapy.rdpcap(temp_pcap)
        
        for session in cap.sessions():
            http_payload = bytes()
            for pkt in cap.sessions()[session]:
                if pkt.haslayer('TCP'):
                    tcp_layer = pkt['TCP']
                    if tcp_layer.dport in [80, 8080] or tcp_layer.sport in [80, 8080]:
                        if tcp_layer.payload:
                            try:
                                http_payload += bytes(tcp_layer.payload)
                            except:
                                pass
            
            if http_payload:
                headers = get_http_headers(http_payload)
                if headers:
                    obj, obj_type = extract_http_object(headers, http_payload)
                    if obj is not None:
                        try:
                            hex_data = codecs.encode(obj, 'hex').decode('ascii')
                        except:
                            hex_data = ''
                        objects.append({
                            'data': hex_data[:200] if hex_data else '',
                            'type': obj_type.hex() if obj_type else 'unknown',
                            'size': len(obj)
                        })
    except Exception as e:
        logger.error(f"Error reading HTTP objects: {e}")
    
    return objects

# ============== STREAM PROCESSING ==============
def load_tcp_streams():
    """Load TCP stream indices from captured packets"""
    streams = []
    http2_streams = []
    
    try:
        temp_pcap = os.path.join(TEMP_DIR, 'tcpstreamread.pcap')
        
        # Write packets to temp file
        with capture_state._lock:
            pkt_list = list(capture_state.pkt_list)
        
        if not pkt_list:
            return [], []
            
        scapy.wrpcap(temp_pcap, pkt_list)
        
        # TCP streams
        try:
            cap = pyshark.FileCapture(temp_pcap, display_filter="tcp.stream", keep_packets=True)
            stream_ids = set()
            for pkt in cap:
                if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'stream'):
                    try:
                        stream_ids.add(int(pkt.tcp.stream))
                    except:
                        pass
            cap.close()
            streams = sorted(list(stream_ids))
        except Exception as e:
            logger.warning(f"TCP stream extraction: {e}")
        
        # HTTP/2 streams
        try:
            cap2 = pyshark.FileCapture(temp_pcap, display_filter="http2", 
                                       override_prefs={'ssl.keylog_file': SSL_LOG_FILE})
            http2_ids = set()
            for pkt in cap2:
                if hasattr(pkt, 'http2') and hasattr(pkt.http2, 'streamid'):
                    try:
                        http2_ids.add(int(pkt.http2.streamid))
                    except:
                        pass
            cap2.close()
            http2_streams = sorted(list(http2_ids))
        except Exception as e:
            logger.warning(f"HTTP/2 parsing: {e}")
        
    except Exception as e:
        logger.error(f"Error loading streams: {e}")
    
    with capture_state._lock:
        capture_state.tcp_streams = streams
        capture_state.http2_streams = http2_streams
    
    socketio.emit('streams_loaded', {
        'tcp_streams': streams,
        'http2_streams': http2_streams
    })
    
    return streams, http2_streams

def get_tcp_stream_data(stream_id):
    """Get TCP stream content"""
    data = {'client': '', 'server': ''}
    try:
        temp_pcap = os.path.join(TEMP_DIR, 'tcpstreamread.pcap')
        
        if not os.path.exists(temp_pcap):
            return data
            
        cap = pyshark.FileCapture(
            temp_pcap,
            display_filter=f'tcp.stream eq {stream_id}',
            override_prefs={'ssl.keylog_file': SSL_LOG_FILE}
        )
        
        for pkt in cap:
            if hasattr(pkt, 'tcp'):
                try:
                    payload = pkt.tcp.payload.binary_value
                    if pkt.tcp.srcport == pkt[pkt.transport_layer].dstport:
                        data['client'] += payload.decode('utf-8', 'replace')
                    else:
                        data['server'] += payload.decode('utf-8', 'replace')
                except:
                    pass
        cap.close()
    except Exception as e:
        logger.error(f"Error getting stream {stream_id}: {e}")
    
    return data

# ============== YARA SCANNING ==============
def load_yara_rules():
    """Load YARA rules from file"""
    try:
        import yara
        if os.path.exists(YARA_RULES_FILE):
            return yara.compile(YARA_RULES_FILE)
    except Exception as e:
        logger.warning(f"YARA not available: {e}")
    return None

def yara_scan_files():
    """Scan extracted files with YARA rules"""
    flagged = []
    try:
        yara_rules = load_yara_rules()
        if not yara_rules:
            return flagged
        
        # Scan extracted TCP flow files
        for f in glob.glob(os.path.join(TCPFLOW_DIR, '*')):
            if os.path.getsize(f) > 0:
                try:
                    matches = yara_rules.match(f)
                    for match in matches:
                        flagged.append({
                            'file': os.path.basename(f),
                            'rule': match.rule,
                            'tags': match.tags,
                            'meta': dict(match.meta)
                        })
                except Exception as e:
                    logger.debug(f"YARA scan on {f}: {e}")
                    pass
    except Exception as e:
        logger.error(f"YARA scan error: {e}")
    
    return flagged

def extract_tcp_flows():
    """Extract TCP flows using tcpflow"""
    try:
        # Clear old files
        for f in glob.glob(os.path.join(TCPFLOW_DIR, '*')):
            try:
                os.remove(f)
            except:
                pass
        
        # Extract from PCAP files
        http_pcap = os.path.join(TEMP_DIR, 'httpstreamread.pcap')
        tcp_pcap = os.path.join(TEMP_DIR, 'tcpstreamread.pcap')
        
        for pcap_file in [http_pcap, tcp_pcap]:
            if os.path.exists(pcap_file):
                try:
                    # Use tcpflow if available
                    subprocess.call(
                        f'tcpflow -a -r "{pcap_file}" -o "{TCPFLOW_DIR}"',
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                except Exception as e:
                    logger.debug(f"tcpflow extraction: {e}")
                    pass
    except Exception as e:
        logger.error(f"TCP flow extraction error: {e}")

# ============== PACKET PROCESSING ==============
def process_packet(pkt):
    """Process each captured packet"""
    if not capture_state.running:
        return

    # Add to packet list
    capture_state.add_packet(pkt)

    # Generate summary
    try:
        summary = pkt.summary()
    except:
        summary = str(pkt)

    # Get protocol for stats
    if 'IP' in pkt:
        proto = proto_name_by_num(pkt['IP'].proto)
        with capture_state._lock:
            capture_state.protocol_stats[proto] += 1
        
        # === CLOSED LOOP: Anomaly Detection ===
        if anomaly_detector and anomaly_detector.enabled:
            try:
                # Build packet dict for anomaly detector
                pkt_dict = {
                    'src': pkt['IP'].src,
                    'dst': pkt['IP'].dst,
                    'proto': proto,
                    'sport': getattr(pkt['IP'], 'sport', 0),
                    'dport': getattr(pkt['IP'], 'dport', 0),
                    'flags': '',
                    'length': len(pkt)
                }
                
                # Add TCP flags if available
                if 'TCP' in pkt:
                    flags = pkt['TCP'].flags
                    pkt_dict['flags'] = str(flags)
                    pkt_dict['length'] = len(pkt)
                
                # Process through anomaly detector
                anomaly = anomaly_detector.process_packet(pkt_dict)
                
                # If anomaly detected, emit it
                if anomaly:
                    anomaly_data = anomaly.to_dict()
                    socketio.emit('new_anomaly', anomaly_data)
                    
            except Exception as e:
                logger.debug(f"Anomaly detection error: {e}")
        # === END CLOSED LOOP ===

    # Check rules
    rule_match = check_packet_rules(pkt)
    
    if rule_match:
        # Get payload
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
            'summary': summary,
            'message': rule_match['message'],
            'src': rule_match['src'],
            'dst': rule_match['dst'],
            'proto': rule_match['proto'],
            'sport': rule_match['sport'],
            'dport': rule_match['dport'],
            'payload': payload[:500]
        }
        
        capture_state.add_alert(alert, payload)
        
        # Emit alert via WebSocket
        socketio.emit('new_alert', alert)
    
    # Emit packet update (throttled to every 10 packets for performance)
    if capture_state.packet_count % 10 == 0:
        socketio.emit('packet_update', {
            'packet_count': capture_state.packet_count,
            'alert_count': capture_state.alert_count,
            'protocol_stats': dict(capture_state.protocol_stats)
        })

# ============== CAPTURE CONTROL ==============
def start_capture(interface):
    """Start packet capture in background thread"""
    if capture_state.running:
        return
    
    capture_state.reset()
    capture_state.running = True
    capture_state.interface = interface
    capture_state.start_time = datetime.now()
    
    def capture_thread():
        try:
            logger.info(f"Starting capture on interface: {interface}")
            scapy.sniff(
                prn=process_packet,
                store=0,
                iface=interface if interface else None,
                stop_filter=lambda x: not capture_state.running
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            capture_state.running = False
        
        # Capture stopped
        logger.info("Capture thread ended")
        load_tcp_streams()
        socketio.emit('capture_stopped', capture_state.get_summary())
    
    thread = threading.Thread(target=capture_thread, daemon=True)
    thread.start()
    
    socketio.emit('capture_started', {'interface': interface})

def stop_capture():
    """Stop packet capture"""
    capture_state.running = False
    # Stream loading is done in capture_thread after sniff stops

# ============== ROUTES ==============
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/interfaces')
def api_interfaces():
    """Get available network interfaces"""
    return jsonify({'interfaces': get_interfaces()})

@app.route('/api/rules', methods=['GET', 'POST'])
def api_rules():
    """Get or update rules"""
    if request.method == 'POST':
        data = request.json
        with open('rules.txt', 'w') as f:
            for rule in data.get('rules', []):
                f.write(rule + '\n')
        load_network_rules()
        return jsonify({'status': 'success'})
    return jsonify({'rules': rules_state['raw_rules']})

@app.route('/api/capture', methods=['POST'])
def api_capture():
    """Control packet capture"""
    data = request.json
    action = data.get('action')
    
    if action == 'start':
        interface = data.get('interface')
        start_capture(interface)
        return jsonify({'status': 'started', 'interface': interface})
    elif action == 'stop':
        stop_capture()
        return jsonify({'status': 'stopped'})
    
    return jsonify({'status': 'unknown'})

@app.route('/api/status')
def api_status():
    """Get current capture status"""
    return jsonify(capture_state.get_summary())

@app.route('/api/protocols')
def api_protocols():
    """Get protocol statistics"""
    return jsonify({'protocols': dict(capture_state.protocol_stats)})

@app.route('/api/packets')
def api_packets():
    """Get recent packets"""
    with capture_state._lock:
        packets = []
        for pkt in list(capture_state.pkt_list)[-50:]:
            try:
                if 'IP' in pkt:
                    packets.append({
                        'src': pkt['IP'].src,
                        'dst': pkt['IP'].dst,
                        'proto': proto_name_by_num(pkt['IP'].proto),
                        'len': len(pkt)
                    })
            except:
                pass
        return jsonify({'packets': packets})

@app.route('/api/alerts')
def api_alerts():
    """Get all alerts"""
    with capture_state._lock:
        return jsonify({
            'alerts': list(capture_state.suspicious_packets[-100:]),
            'payloads': list(capture_state.sus_readable_payloads[-100:])
        })

@app.route('/api/streams')
def api_streams():
    """Get TCP/HTTP2 streams"""
    return jsonify({
        'tcp_streams': capture_state.tcp_streams,
        'http2_streams': capture_state.http2_streams
    })

@app.route('/api/stream/<int:stream_id>')
def api_stream(stream_id):
    """Get TCP stream content"""
    data = get_tcp_stream_data(stream_id)
    return jsonify(data)

@app.route('/api/save_pcap', methods=['POST'])
def api_save_pcap():
    """Save captured packets to PCAP file"""
    data = request.json
    filename = data.get('filename', f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
    filepath = os.path.join(PCAP_DIR, filename)
    
    try:
        with capture_state._lock:
            pkt_list = list(capture_state.pkt_list)
        
        if pkt_list:
            scapy.wrpcap(filepath, pkt_list)
            return jsonify({'status': 'success', 'filename': filename})
        else:
            return jsonify({'status': 'error', 'message': 'No packets to save'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/upload_pcap', methods=['POST'])
def api_upload_pcap():
    """Upload and analyze PCAP file"""
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'})
    
    filepath = os.path.join(TEMP_DIR, 'uploaded.pcap')
    file.save(filepath)
    
    # Analyze uploaded PCAP
    try:
        cap = scapy.rdpcap(filepath)
        for pkt in cap:
            process_packet(pkt)
        load_tcp_streams()
        return jsonify({
            'status': 'success', 
            'packets': capture_state.packet_count,
            'alerts': capture_state.alert_count
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/yara/scan', methods=['POST'])
def api_yara_scan():
    """Run YARA scan on extracted streams"""
    extract_tcp_flows()
    results = yara_scan_files()
    return jsonify({'status': 'success', 'results': results})

@app.route('/api/http/objects')
def api_http_objects():
    """Get HTTP objects"""
    objects = read_http_objects()
    return jsonify({'objects': objects})

# ============== CLOSED LOOP / ANOMALY DETECTION ==============
# Initialize closed-loop components
anomaly_detector = None
closed_loop_initialized = False

def init_closed_loop():
    """Initialize closed-loop anomaly detection"""
    global anomaly_detector, closed_loop_initialized
    if closed_loop_initialized:
        return
    try:
        from closed_loop.anomaly_detector import create_anomaly_detector
        anomaly_detector = create_anomaly_detector({'window_size': 10, 'threshold': 0.5})
        logger.info("Closed-loop anomaly detector initialized")
        closed_loop_initialized = True
    except Exception as e:
        logger.warning(f"Could not initialize anomaly detector: {e}")
        anomaly_detector = None

# Initialize on module load
init_closed_loop()

@app.route('/api/closed-loop/status')
def api_closed_loop_status():
    """Get closed-loop detection status"""
    if anomaly_detector is None:
        # Initialize if not done
        init_closed_loop()
    
    if anomaly_detector:
        stats = anomaly_detector.get_statistics()
        return jsonify({
            'enabled': anomaly_detector.enabled,
            'stats': stats,
            'active_anomalies': anomaly_detector.get_active_anomalies()
        })
    return jsonify({'enabled': False, 'error': 'Anomaly detector not available'})

@app.route('/api/closed-loop/anomalies')
def api_closed_loop_anomalies():
    """Get recent anomalies from closed-loop detection"""
    if anomaly_detector:
        return jsonify({
            'anomalies': anomaly_detector.get_recent_anomalies(50)
        })
    return jsonify({'anomalies': []})

@app.route('/api/closed-loop/config', methods=['POST'])
def api_closed_loop_config():
    """Configure closed-loop detection settings"""
    if anomaly_detector is None:
        init_closed_loop()
    
    if anomaly_detector:
        data = request.json or {}
        
        # Handle auto_generate_rules toggle (learning toggle)
        if 'auto_generate_rules' in data:
            if data['auto_generate_rules']:
                anomaly_detector.enable()
            else:
                anomaly_detector.disable()
        
        # Handle threshold adjustment
        if 'threshold' in data:
            anomaly_detector.detection_threshold = float(data['threshold'])
        
        # Handle window size adjustment
        if 'window_size' in data:
            anomaly_detector.window_size = int(data['window_size'])
        
        return jsonify({
            'enabled': anomaly_detector.enabled,
            'threshold': anomaly_detector.detection_threshold,
            'window_size': anomaly_detector.window_size
        })
    return jsonify({'enabled': False, 'error': 'Anomaly detector not available'})

# ============== YARA STATUS ==============
@app.route('/api/yara/status')
def api_yara_status():
    """Get YARA scanner status"""
    try:
        import yara
        yara_available = True
    except ImportError:
        yara_available = False
    
    rules_loaded = os.path.exists(YARA_RULES_FILE) if yara_available else False
    
    return jsonify({
        'available': yara_available,
        'rules_loaded': rules_loaded,
        'rules_file': YARA_RULES_FILE
    })

@app.route('/saved_pcap/<path:filename>')
def download_pcap(filename):
    """Download saved PCAP file"""
    filepath = os.path.join(PCAP_DIR, filename)
    if os.path.exists(filepath):
        return send_file(
            filepath,
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    return jsonify({'error': 'File not found'}), 404

# ============== FEDERATION STATE ==============
federation_state = {
    'is_running': False,
    'current_round': 0,
    'total_rounds': 0,
    'clients': {},
    'global_rules': [],
    'results': {},
    'last_update': None,
    'logs': []
}

# ============== FEDERATION ENDPOINTS ==============
@app.route('/api/federation/status')
def federation_status():
    """Get federated learning status"""
    return jsonify(federation_state)

@app.route('/api/federation/start', methods=['POST'])
def federation_start():
    """Start federated learning session"""
    data = request.json or {}
    num_rounds = data.get('num_rounds', 3)
    scenario = data.get('scenario', 'non_iid')
    
    # Use lowercase keys to match frontend expectations
    federation_state['is_running'] = True
    federation_state['total_rounds'] = num_rounds
    federation_state['current_round'] = 0
    federation_state['clients'] = {
        'client_a': {'status': 'ready', 'pattern': 'port_scan', 'packets': 0, 'anomalies': 0, 'rules': 0},
        'client_b': {'status': 'ready', 'pattern': 'syn_flood', 'packets': 0, 'anomalies': 0, 'rules': 0},
        'client_c': {'status': 'ready', 'pattern': 'mixed', 'packets': 0, 'anomalies': 0, 'rules': 0}
    }
    federation_state['last_update'] = datetime.now().isoformat()
    
    # Run federation in background with demo simulation only
    def run_federation():
        try:
            # Always use demo simulation for the dashboard
            logger.info("Starting federation simulation...")
            
            for round_num in range(1, num_rounds + 1):
                if not federation_state['is_running']:
                    break
                federation_state['current_round'] = round_num
                
                # Simulate client data for each round
                for client_id in ['client_a', 'client_b', 'client_c']:
                    federation_state['clients'][client_id]['packets'] = 500 + (round_num * 100)
                    federation_state['clients'][client_id]['anomalies'] = round_num * 3
                    federation_state['clients'][client_id]['rules'] = round_num * 2
                
                # Add some global rules after first round
                if round_num >= 1:
                    federation_state['global_rules'] = [
                        f"alert tcp any any -> 10.0.0.0/24 any (msg:'Global SYN Flood Rule R{round_num}'; flags:S; sid:100{round_num}01; rev:1;)",
                        f"alert tcp any any -> 10.0.0.0/24 any (msg:'Global Port Scan Rule R{round_num}'; sid:100{round_num}02; rev:1;)",
                        f"alert udp any any -> 10.0.0.0/24 53 (msg:'Global DNS Amp Rule R{round_num}'; sid:100{round_num}03; rev:1;)",
                    ]
                
                logger.info(f"Federation round {round_num}/{num_rounds} completed")
                
                # Emit update via socket
                socketio.emit('packet_update', {
                    'packet_count': capture_state.packet_count,
                    'alert_count': capture_state.alert_count,
                    'protocol_stats': dict(capture_state.protocol_stats)
                })
                
                time.sleep(1.5)  # Simulate round time
                
            federation_state['results'] = {
                'rounds_completed': federation_state['current_round'],
                'scenario': scenario,
                'final_global_rules': federation_state['global_rules']
            }
                    
        except Exception as e:
            logger.error(f"Federation error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            federation_state['is_running'] = False
            federation_state['current_round'] = 0
    
    thread = threading.Thread(target=run_federation, daemon=True)
    thread.start()
    
    return jsonify({'status': 'started', 'num_rounds': num_rounds, 'scenario': scenario})

@app.route('/api/federation/stop', methods=['POST'])
def federation_stop():
    """Stop federated learning"""
    federation_state['is_running'] = False
    return jsonify({'status': 'stopped'})

@app.route('/api/federation/results')
def federation_results():
    """Get federation results"""
    return jsonify(federation_state.get('results', {}))

@app.route('/api/federation/scenarios')
def federation_scenarios():
    """Get available scenarios"""
    return jsonify({
        'scenarios': ['iid', 'non_iid', 'zero_day'],
        'descriptions': {
            'iid': 'Independent and Identically Distributed - All clients see same attack patterns',
            'non_iid': 'Non-IID - Different clients see different attack patterns',
            'zero_day': 'Zero-Day - New attack type introduced mid-training'
        }
    })

@app.route('/api/federation/global-rules')
def federation_global_rules():
    """Get global rules from consensus"""
    return jsonify({'global_rules': federation_state.get('global_rules', [])})

# ============== DEMO/SIMULATION MODE ==============
import random

demo_state = {
    'running': False,
    'packets_generated': 0,
    'mode': 'mixed'  # normal, port_scan, syn_flood, ddos, icmp_flood, mixed
}

def generate_demo_packet(mode='normal'):
    """Generate a synthetic packet for demo mode"""
    # Common source IPs for demo
    src_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.50', '172.16.0.10']
    dst_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5']
    protocols = ['tcp', 'udp', 'icmp']
    common_ports = [80, 443, 22, 53, 8080, 3306, 21]
    
    if mode == 'port_scan':
        # Simulate port scan - many ports from same IP
        src_ip = '192.168.1.200'
        dst_ip = random.choice(['10.0.0.10', '10.0.0.20', '10.0.0.30'])
        dport = random.randint(1, 1024)  # Scanning many ports
        proto = 'tcp'
        flags = 'S'
    elif mode == 'syn_flood':
        # Simulate SYN flood - high rate from same IP
        src_ip = random.choice(['192.168.1.250', '10.10.10.5'])
        dst_ip = '10.0.0.1'
        dport = 80
        proto = 'tcp'
        flags = 'S'
    elif mode == 'ddos':
        # Simulate DDoS - many source IPs hitting same target
        src_ip = f'10.100.{random.randint(1,255)}.{random.randint(1,255)}'
        dst_ip = '10.0.0.1'
        dport = 80
        proto = 'tcp'
        flags = 'S'
    elif mode == 'icmp_flood':
        # Simulate ICMP flood
        src_ip = '192.168.1.180'
        dst_ip = '10.0.0.1'
        dport = 0
        proto = 'icmp'
        flags = ''
    else:
        # Normal traffic
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        dport = random.choice(common_ports)
        proto = random.choice(protocols)
        flags = 'S' if proto == 'tcp' and random.random() > 0.5 else 'A'
    
    return {
        'src': src_ip,
        'dst': dst_ip,
        'proto': proto,
        'sport': random.randint(1024, 65535),
        'dport': dport,
        'flags': flags,
        'length': random.randint(64, 1500)
    }

def run_demo_simulation():
    """Background thread for demo simulation"""
    global demo_state
    
    # Set capture state to running so packets get processed
    capture_state.running = True
    capture_state.start_time = datetime.now()
    
    while demo_state['running']:
        try:
            # Generate packet based on mode
            mode = demo_state['mode']
            if mode == 'mixed':
                # Randomly choose attack type
                rand_val = random.random()
                if rand_val < 0.7:
                    mode = 'normal'
                elif rand_val < 0.85:
                    mode = 'port_scan'
                elif rand_val < 0.95:
                    mode = 'syn_flood'
                else:
                    mode = random.choice(['ddos', 'icmp_flood'])
            
            pkt_dict = generate_demo_packet(mode)
            
            # Create a mock scapy packet-like object for processing
            class MockPacket:
                def __init__(self, d):
                    self.data = d
                    self.src = d.get('src', '')
                    self.dst = d.get('dst', '')
                    self.sport = d.get('sport', 0)
                    self.dport = d.get('dport', 0)
                    self.len = d.get('length', 64)
                    
                    # Set protocol as NAME (will be converted to number by proto property)
                    self._proto_name = d.get('proto', 'tcp')
                    
                    # Protocol number mapping (for scapy compatibility)
                    self._proto_num = {
                        'tcp': 6,
                        'udp': 17, 
                        'icmp': 1,
                        'arp': 28,
                        'dns': 17  # DNS uses UDP
                    }.get(self._proto_name.lower(), 0)
                
                @property
                def proto(self):
                    """Return protocol NUMBER for process_packet function"""
                    return self._proto_num
                    
                def summary(self):
                    return f"{self._proto_name.upper()} {self.data['src']}:{self.data['sport']} -> {self.data['dst']}:{self.data['dport']}"
                
                def __getitem__(self, key):
                    if key == 'IP':
                        return self
                    if key == 'TCP' and self._proto_name.lower() == 'tcp':
                        return self
                    if key == 'UDP' and self._proto_name.lower() == 'udp':
                        return self
                    if key == 'ICMP' and self._proto_name.lower() == 'icmp':
                        return self
                    raise KeyError(key)
                
                def __contains__(self, key):
                    if key == 'IP':
                        return True
                    if key == 'TCP' and self._proto_name.lower() == 'tcp':
                        return True
                    if key == 'UDP' and self._proto_name.lower() == 'udp':
                        return True
                    if key == 'ICMP' and self._proto_name.lower() == 'icmp':
                        return True
                    return False
                
                def __len__(self):
                    return self.len
            
            mock_pkt = MockPacket(pkt_dict)
            
            # Process packet through the main processing function
            # This will add it to capture_state.pkt_list and check rules
            process_packet(mock_pkt)
            
            # Also process through anomaly detector directly
            if anomaly_detector and anomaly_detector.enabled:
                anomaly = anomaly_detector.process_packet(pkt_dict)
                if anomaly:
                    # Emit via WebSocket
                    socketio.emit('new_anomaly', anomaly.to_dict())
            
            demo_state['packets_generated'] += 1
            
            # Update protocol stats
            with capture_state._lock:
                capture_state.protocol_stats[pkt_dict['proto']] += 1
            
            # Emit packet update every 5 packets
            if demo_state['packets_generated'] % 5 == 0:
                socketio.emit('packet_update', {
                    'packet_count': capture_state.packet_count,
                    'alert_count': capture_state.alert_count,
                    'protocol_stats': dict(capture_state.protocol_stats)
                })
            
            # Occasionally trigger an alert for attack patterns
            if mode != 'normal' and random.random() < 0.15:
                alert = {
                    'id': capture_state.alert_count + 1,
                    'timestamp': datetime.now().isoformat(),
                    'summary': f"DETECTED: {mode.upper()} attack pattern",
                    'message': f'Suspicious {mode.replace("_", " ").title()} traffic detected',
                    'src': pkt_dict['src'],
                    'dst': pkt_dict['dst'],
                    'proto': pkt_dict['proto'],
                    'sport': pkt_dict['sport'],
                    'dport': pkt_dict['dport'],
                    'payload': ''
                }
                capture_state.add_alert(alert, '')
                socketio.emit('new_alert', alert)
            
            # Sleep briefly for simulation speed
            time.sleep(0.15)
            
        except Exception as e:
            logger.error(f"Demo simulation error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(1)
    
    # Reset capture state when demo stops
    capture_state.running = False

# Demo mode endpoints
@app.route('/api/demo/start', methods=['POST'])
def api_demo_start():
    """Start demo mode with synthetic traffic"""
    global demo_state
    
    if demo_state['running']:
        return jsonify({'status': 'already_running'})
    
    data = request.json or {}
    mode = data.get('mode', 'mixed')
    
    demo_state['running'] = True
    demo_state['mode'] = mode
    demo_state['packets_generated'] = 0
    
    # Start simulation in background
    thread = threading.Thread(target=run_demo_simulation, daemon=True)
    thread.start()
    
    logger.info(f"Demo mode started: {mode}")
    return jsonify({'status': 'started', 'mode': mode})

@app.route('/api/demo/stop', methods=['POST'])
def api_demo_stop():
    """Stop demo mode"""
    global demo_state
    demo_state['running'] = False
    logger.info("Demo mode stopped")
    return jsonify({'status': 'stopped', 'packets_generated': demo_state['packets_generated']})

@app.route('/api/demo/status')
def api_demo_status():
    """Get demo mode status"""
    return jsonify({
        'running': demo_state['running'],
        'mode': demo_state['mode'],
        'packets_generated': demo_state['packets_generated']
    })

@app.route('/api/demo/set_mode', methods=['POST'])
def api_demo_set_mode():
    """Set demo mode type"""
    data = request.json or {}
    mode = data.get('mode', 'mixed')
    demo_state['mode'] = mode
    return jsonify({'status': 'ok', 'mode': mode})

# ============== SOCKET EVENTS ==============
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info('Client connected')
    emit('connected', {'status': 'connected'})
    
    # Send current state
    emit('packet_update', {
        'packet_count': capture_state.packet_count,
        'alert_count': capture_state.alert_count,
        'protocol_stats': dict(capture_state.protocol_stats)
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info('Client disconnected')

# ============== INITIALIZATION ==============
def init_app():
    """Initialize application"""
    load_network_rules()
    interfaces = get_interfaces()
    logger.info(f"Initialized with {len(interfaces)} interfaces")
    logger.info(f"Static files: {STATIC_DIR}")
    logger.info(f"Templates: {TEMPLATE_DIR}")

if __name__ == '__main__':
    init_app()
    
    # For development
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    
    logger.info(f"Starting NIDS Dashboard on {host}:{port}")
    
    socketio.run(app, 
                 host=host, 
                 port=port, 
                 debug=True, 
                 allow_unsafe_werkzeug=True,
                 use_reloader=False)  # Disable reloader to prevent double threads

