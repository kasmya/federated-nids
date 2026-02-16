#!/usr/bin/env python3
"""
Real-Time Packet Capture Trainer
Captures live network traffic to build adaptive baselines and improve detection
"""

import os
import sys
import json
import time
import threading
import logging
import random
import socket
from collections import defaultdict, deque
from datetime import datetime
import statistics

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Try to import scapy
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - using simulation mode")


class RealTimePacketCapture:
    """
    Captures real network traffic and builds training data for the NIDS
    """
    
    def __init__(self, interface=None, max_packets=10000):
        self.interface = interface
        self.max_packets = max_packets
        
        # Capture state
        self.running = False
        self.packets_captured = []
        self.packet_times = deque(maxlen=1000)
        
        # Feature tracking
        self.ip_features = defaultdict(lambda: {
            'packets': deque(maxlen=500),
            'ports': set(),
            'dst_ips': set(),
            'protocols': defaultdict(int),
            'bytes_sent': 0,
            'first_seen': time.time(),
            'tcp_flags': defaultdict(int),
            'packet_sizes': deque(maxlen=100)
        })
        
        # Global stats
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'unique_ips': set()
        }
        
        self.lock = threading.RLock()
    
    def start_capture(self):
        """Start capturing packets on the interface"""
        if self.running:
            logger.warning("Capture already running")
            return
        
        self.running = True
        
        if SCAPY_AVAILABLE:
            thread = threading.Thread(target=self._capture_loop, daemon=True)
            thread.start()
            logger.info(f"Started capture on interface: {self.interface or 'default'}")
        else:
            logger.warning("Scapy not available, capture not started")
    
    def stop_capture(self):
        """Stop capturing packets"""
        self.running = False
        logger.info(f"Stopped capture. Total packets: {len(self.packets_captured)}")
    
    def _capture_loop(self):
        """Main capture loop"""
        try:
            scapy.sniff(
                prn=self._process_packet,
                store=0,
                iface=self.interface,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.running = False
    
    def _process_packet(self, pkt):
        """Process a captured packet"""
        if not self.running:
            return
        
        with self.lock:
            self.stats['total_packets'] += 1
            
            if 'IP' not in pkt:
                return
            
            # Extract packet info
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
            proto = 'tcp' if pkt.haslayer('TCP') else 'udp' if pkt.haslayer('UDP') else 'icmp' if pkt.haslayer('ICMP') else 'other'
            length = len(pkt)
            
            self.stats['total_bytes'] += length
            self.stats['protocols'][proto] += 1
            self.stats['unique_ips'].add(src_ip)
            
            # Track per-IP features
            ip_data = self.ip_features[src_ip]
            now = time.time()
            ip_data['packets'].append(now)
            ip_data['bytes_sent'] += length
            ip_data['packet_sizes'].append(length)
            ip_data['protocols'][proto] += 1
            
            # Track ports
            if pkt.haslayer('TCP') or pkt.haslayer('UDP'):
                dport = pkt.dport if pkt.haslayer('TCP') else pkt.dport
                sport = pkt.sport if pkt.haslayer('TCP') else pkt.sport
                ip_data['ports'].add(dport)
            
            # Track TCP flags
            if pkt.haslayer('TCP'):
                flags = str(pkt['TCP'].flags)
                ip_data['tcp_flags'][flags] += 1
            
            # Track destination IPs
            ip_data['dst_ips'].add(dst_ip)
            
            # Store packet
            self.packets_captured.append({
                'timestamp': now,
                'src': src_ip,
                'dst': dst_ip,
                'proto': proto,
                'sport': getattr(pkt, 'sport', 0) if pkt.haslayer('TCP') or pkt.haslayer('UDP') else 0,
                'dport': getattr(pkt, 'dport', 0) if pkt.haslayer('TCP') or pkt.haslayer('UDP') else 0,
                'length': length,
                'flags': str(pkt['TCP'].flags) if pkt.haslayer('TCP') else ''
            })
            
            # Limit stored packets
            if len(self.packets_captured) > self.max_packets:
                self.packets_captured = self.packets_captured[-self.max_packets:]
    
    def get_captured_packets(self):
        """Get all captured packets"""
        with self.lock:
            return list(self.packets_captured)
    
    def get_statistics(self):
        """Get capture statistics"""
        with self.lock:
            return {
                'total_packets': self.stats['total_packets'],
                'total_bytes': self.stats['total_bytes'],
                'unique_ips': len(self.stats['unique_ips']),
                'protocols': dict(self.stats['protocols']),
                'running': self.running
            }
    
    def extract_features_for_ip(self, src_ip, window_seconds=10):
        """Extract features for a specific IP within a time window"""
        with self.lock:
            if src_ip not in self.ip_features:
                return None
            
            ip_data = self.ip_features[src_ip]
            now = time.time()
            window_start = now - window_seconds
            
            # Filter packets in window
            recent_packets = [t for t in ip_data['packets'] if t > window_start]
            
            if not recent_packets:
                return None
            
            features = {
                'src_ip': src_ip,
                'timestamp': now,
                'packet_rate': len(recent_packets) / window_seconds,
                'port_diversity': len(ip_data['ports']),
                'avg_packet_size': statistics.mean(ip_data['packet_sizes']) if ip_data['packet_sizes'] else 64,
                'connection_rate': ip_data['tcp_flags'].get('S', 0) / max(1, now - ip_data['first_seen']),
                'unique_dst_ips': len(ip_data['dst_ips']),
                'bytes_per_second': ip_data['bytes_sent'] / max(1, now - ip_data['first_seen']),
                'protocols': dict(ip_data['protocols']),
                'tcp_flags': dict(ip_data['tcp_flags'])
            }
            
            return features


class AdaptiveThresholdLearner:
    """
    Learns optimal thresholds from captured traffic
    Uses statistical methods to determine anomaly boundaries
    """
    
    def __init__(self, learning_window=100, percentile=95):
        """
        Args:
            learning_window: Number of samples to collect before computing thresholds
            percentile: Percentile to use for threshold (e.g., 95 = mean + 2*std)
        """
        self.learning_window = learning_window
        self.percentile = percentile
        
        # Feature samples for each metric
        self.samples = defaultdict(lambda: deque(maxlen=learning_window))
        
        # Learned thresholds
        self.thresholds = {
            'port_diversity': {'value': 5, 'method': 'fixed'},
            'connection_rate': {'value': 3, 'method': 'fixed'},
            'packet_rate': {'value': 10, 'method': 'fixed'},
            'unique_dst_ips': {'value': 5, 'method': 'fixed'},
            'bytes_per_second': {'value': 500, 'method': 'fixed'}
        }
        
        self.learning_complete = False
        self.lock = threading.RLock()
    
    def add_sample(self, features):
        """Add a feature sample for learning"""
        with self.lock:
            # Collect samples for each feature
            for feature_name in self.thresholds.keys():
                if feature_name in features:
                    value = features[feature_name]
                    if value is not None and value >= 0:
                        self.samples[feature_name].append(value)
            
            # Check if we have enough samples
            if not self.learning_complete:
                self._compute_thresholds()
    
    def _compute_thresholds(self):
        """Compute optimal thresholds from collected samples"""
        min_samples = 20  # Need at least this many samples
        
        for feature_name, sample_deque in self.samples.items():
            if len(sample_deque) < min_samples:
                continue
            
            samples = list(sample_deque)
            
            # Calculate mean and std
            mean = statistics.mean(samples)
            std = statistics.stdev(samples) if len(samples) > 1 else 0
            
            # Use percentile-based threshold
            # For normal traffic, threshold = mean + k*std where k is determined by percentile
            # Higher percentile = more conservative (fewer false positives)
            if std > 0:
                # Use 95th percentile approach
                sorted_samples = sorted(samples)
                percentile_idx = int(len(sorted_samples) * (self.percentile / 100.0))
                percentile_idx = min(percentile_idx, len(sorted_samples) - 1)
                percentile_value = sorted_samples[percentile_idx] if sorted_samples else mean + 2 * std
                
                # Use larger of: percentile value or mean + 2*std
                threshold = max(percentile_value, mean + 2 * std)
            else:
                # If no variance, use mean * 2
                threshold = mean * 2 if mean > 0 else 1
            
            # Store learned threshold
            self.thresholds[feature_name] = {
                'value': threshold,
                'method': 'learned',
                'mean': mean,
                'std': std,
                'samples': len(samples)
            }
        
        # Check if learning is complete
        learned_count = sum(1 for t in self.thresholds.values() if t['method'] == 'learned')
        if learned_count >= len(self.thresholds) * 0.8:  # 80% of features learned
            self.learning_complete = True
            logger.info(f"Threshold learning complete: {learned_count}/{len(self.thresholds)} features learned")
    
    def get_threshold(self, feature_name):
        """Get threshold for a feature"""
        with self.lock:
            if feature_name in self.thresholds:
                return self.thresholds[feature_name]['value']
            return 1.0  # Default fallback
    
    def get_thresholds(self):
        """Get all learned thresholds"""
        with self.lock:
            return dict(self.thresholds)
    
    def is_learning_complete(self):
        """Check if threshold learning is complete"""
        with self.lock:
            return self.learning_complete
    
    def reset(self):
        """Reset learned thresholds"""
        with self.lock:
            self.samples.clear()
            self.thresholds = {
                'port_diversity': {'value': 5, 'method': 'fixed'},
                'connection_rate': {'value': 3, 'method': 'fixed'},
                'packet_rate': {'value': 10, 'method': 'fixed'},
                'unique_dst_ips': {'value': 5, 'method': 'fixed'},
                'bytes_per_second': {'value': 500, 'method': 'fixed'}
            }
            self.learning_complete = False


class AttackSimulator:
    """
    Simulates various attack types for generating labeled training data
    """
    
    def __init__(self):
        self.attack_types = [
            'port_scan',
            'syn_flood',
            'ddos',
            'ssh_bruteforce',
            'dns_amplification'
        ]
    
    def generate_attack_packet(self, attack_type, src_ip=None, dst_ip=None):
        """Generate a packet that represents an attack"""
        if src_ip is None:
            src_ip = f"192.168.1.{random.randint(100, 200)}"
        if dst_ip is None:
            dst_ip = "10.0.0.1"
        
        packet = {
            'timestamp': time.time(),
            'src': src_ip,
            'dst': dst_ip,
            'proto': 'tcp',
            'sport': random.randint(49152, 65535),
            'dport': 80,
            'length': 64,
            'flags': 'S',
            'attack_type': attack_type,
            'is_attack': True
        }
        
        if attack_type == 'port_scan':
            packet['dport'] = random.randint(1, 1000)
            packet['flags'] = 'S'
            packet['proto'] = 'tcp'
        
        elif attack_type == 'syn_flood':
            packet['dport'] = 80
            packet['flags'] = 'S'
            packet['proto'] = 'tcp'
            packet['length'] = 64
        
        elif attack_type == 'ddos':
            packet['dport'] = random.choice([80, 443, 22])
            packet['flags'] = 'S'
            packet['proto'] = 'tcp'
        
        elif attack_type == 'ssh_bruteforce':
            packet['dport'] = 22
            packet['flags'] = 'PA'
            packet['proto'] = 'tcp'
        
        elif attack_type == 'dns_amplification':
            packet['dport'] = 53
            packet['proto'] = 'udp'
        
        return packet
    
    def generate_attack_sequence(self, attack_type, count=50, src_ip=None):
        """Generate a sequence of attack packets"""
        packets = []
        dst_ip = random.choice(['8.8.8.8', '1.1.1.1', '10.0.0.1'])
        
        for i in range(count):
            pkt = self.generate_attack_packet(attack_type, src_ip, dst_ip)
            packets.append(pkt)
        
        return packets


class TrainingDataCollector:
    """
    Collects training data from real traffic and simulated attacks
    Builds labeled dataset for improving detection
    """
    
    def __init__(self):
        self.normal_traffic = []  # Labeled normal traffic
        self.attack_traffic = []   # Labeled attack traffic
        
        self.attack_simulator = AttackSimulator()
        self.threshold_learner = AdaptiveThresholdLearner()
        
        self.lock = threading.RLock()
    
    def add_normal_sample(self, features):
        """Add a normal traffic sample"""
        with self.lock:
            self.normal_traffic.append({
                'features': features,
                'label': 'normal',
                'timestamp': time.time()
            })
            self.threshold_learner.add_sample(features)
    
    def add_attack_sample(self, features, attack_type):
        """Add an attack traffic sample"""
        with self.lock:
            self.attack_traffic.append({
                'features': features,
                'label': attack_type,
                'attack_type': attack_type,
                'timestamp': time.time()
            })
    
    def simulate_attacks_and_collect(self, attack_types=None, packets_per_attack=50):
        """Simulate attacks and collect training data"""
        if attack_types is None:
            attack_types = self.attack_simulator.attack_types
        
        for attack_type in attack_types:
            # Generate attack packets
            attack_packets = self.attack_simulator.generate_attack_sequence(
                attack_type, 
                count=packets_per_attack
            )
            
            # Extract features from attack packets
            for pkt in attack_packets:
                # Create feature dict from packet
                features = {
                    'src_ip': pkt['src'],
                    'timestamp': pkt['timestamp'],
                    'packet_rate': 10,  # Simulated
                    'port_diversity': 1 if pkt['dport'] else 0,
                    'connection_rate': 1,
                    'unique_dst_ips': 1,
                    'bytes_per_second': 1000,
                }
                
                if attack_type == 'port_scan':
                    features['port_diversity'] = random.randint(10, 100)
                    features['connection_rate'] = random.randint(5, 20)
                
                self.add_attack_sample(features, attack_type)
        
        logger.info(f"Collected {len(self.normal_traffic)} normal, {len(self.attack_traffic)} attack samples")
    
    def get_training_data(self):
        """Get all training data"""
        with self.lock:
            return {
                'normal': list(self.normal_traffic),
                'attack': list(self.attack_traffic),
                'thresholds': self.threshold_learner.get_thresholds()
            }
    
    def export_training_data(self, filepath):
        """Export training data to file"""
        with self.lock:
            data = {
                'normal': self.normal_traffic,
                'attack': self.attack_traffic,
                'thresholds': self.threshold_learner.get_thresholds(),
                'export_time': datetime.now().isoformat()
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Exported training data to {filepath}")
            return filepath


def proto_name_by_num(proto_num):
    """Convert protocol number to name"""
    protocols = {
        1: 'icmp',
        6: 'tcp',
        17: 'udp'
    }
    return protocols.get(proto_num, 'other')


def get_available_interfaces():
    """Get list of available network interfaces"""
    interfaces = []
    
    if SCAPY_AVAILABLE:
        try:
            from scapy.arch import get_if_list
            for iface in get_if_list():
                try:
                    ip = scapy.get_if_addr(iface)
                    interfaces.append({'name': iface, 'ip': str(ip)})
                except:
                    interfaces.append({'name': iface, 'ip': 'N/A'})
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
    
    # Fallback
    if not interfaces:
        interfaces = [
            {'name': 'en0', 'ip': 'Primary'},
            {'name': 'lo0', 'ip': '127.0.0.1'}
        ]
    
    return interfaces


def run_training_session(interface=None, duration=60, capture_only=True):
    """
    Run a training session to collect data
    
    Args:
        interface: Network interface to capture on
        duration: Duration in seconds (0 = infinite)
        capture_only: If True, only capture normal traffic
    
    Returns:
        TrainingDataCollector with collected data
    """
    collector = TrainingDataCollector()
    capture = RealTimePacketCapture(interface=interface)
    
    logger.info(f"Starting training session (duration={duration}s, capture_only={capture_only})")
    
    # Start capture
    capture.start_capture()
    
    # If not capture-only, also simulate attacks
    if not capture_only:
        logger.info("Simulating attacks for labeled training data...")
        collector.simulate_attacks_and_collect()
    
    # Run for specified duration
    if duration > 0:
        logger.info(f"Collecting traffic for {duration} seconds...")
        time.sleep(duration)
        capture.stop_capture()
    else:
        try:
            while True:
                time.sleep(10)
                stats = capture.get_statistics()
                logger.info(f"Packets captured: {stats['total_packets']}")
        except KeyboardInterrupt:
            logger.info("Stopping capture...")
            capture.stop_capture()
    
    # Extract features from captured packets and add to collector
    logger.info("Extracting features from captured traffic...")
    captured = capture.get_captured_packets()
    
    # Group packets by source IP
    ip_packets = defaultdict(list)
    for pkt in captured:
        ip_packets[pkt['src']].append(pkt)
    
    # Extract features per IP
    for src_ip, packets in ip_packets.items():
        if len(packets) >= 3:  # Need at least 3 packets
            features = {
                'src_ip': src_ip,
                'timestamp': time.time(),
                'packet_rate': len(packets) / max(1, packets[-1]['timestamp'] - packets[0]['timestamp']),
                'port_diversity': len(set(p['dport'] for p in packets)),
                'unique_dst_ips': len(set(p['dst'] for p in packets)),
                'bytes_per_second': sum(p['length'] for p in packets) / max(1, packets[-1]['timestamp'] - packets[0]['timestamp']),
                'connection_rate': sum(1 for p in packets if p.get('flags') == 'S') / max(1, packets[-1]['timestamp'] - packets[0]['timestamp'])
            }
            collector.add_normal_sample(features)
    
    logger.info(f"Training session complete. Collected {len(collector.normal_traffic)} samples")
    
    return collector, capture


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-Time Packet Capture Trainer')
    parser.add_argument('-i', '--interface', default=None, help='Network interface to capture on')
    parser.add_argument('-d', '--duration', type=int, default=60, help='Capture duration in seconds')
    parser.add_argument('--simulate-attacks', action='store_true', help='Simulate attacks for training')
    parser.add_argument('-o', '--output', default='training_data.json', help='Output file for training data')
    
    args = parser.parse_args()
    
    # Show available interfaces
    print("Available interfaces:")
    for iface in get_available_interfaces():
        print(f"  {iface['name']}: {iface['ip']}")
    print()
    
    # Run training session
    collector, capture = run_training_session(
        interface=args.interface,
        duration=args.duration,
        capture_only=not args.simulate_attacks
    )
    
    # Export training data
    collector.export_training_data(args.output)
    
    # Show learned thresholds
    print("\nLearned Thresholds:")
    thresholds = collector.threshold_learner.get_thresholds()
    for feature, threshold in thresholds.items():
        print(f"  {feature}: {threshold}")

