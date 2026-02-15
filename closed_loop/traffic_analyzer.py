#!/usr/bin/env python3
"""
Traffic Analyzer - Feature Extraction for NIDS
Extracts 10 key features from network packets for anomaly detection
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import logging

logger = logging.getLogger(__name__)


class TrafficFeatureExtractor:
    """Extracts features from network traffic for anomaly detection"""
    
    def __init__(self, window_size_seconds=10):
        self.window_size = window_size_seconds
        
        # Per-source IP tracking
        self.ip_traffic = defaultdict(lambda: {
            'packets': deque(maxlen=1000),
            'packet_sizes': deque(maxlen=100),
            'dst_ports': set(),
            'dst_ips': set(),
            'protocols': defaultdict(int),
            'tcp_flags': defaultdict(int),
            'dns_queries': deque(maxlen=50),
            'icmp_count': 0,
            'bytes_sent': 0,
            'first_seen': None,
            'last_seen': None,
            'connection_attempts': 0
        })
        
        # Global tracking
        self.global_packet_times = deque(maxlen=10000)
        self.lock = threading.RLock()
    
    def extract_features(self, packet_dict):
        """
        Extract features from a packet dictionary.
        packet_dict should contain: src, dst, proto, sport, dport, flags, length
        Returns: dict of features
        """
        with self.lock:
            src_ip = packet_dict.get('src', 'unknown')
            now = time.time()
            
            # Get or create IP traffic record
            traffic = self.ip_traffic[src_ip]
            
            # Initialize timing
            if traffic['first_seen'] is None:
                traffic['first_seen'] = now
            
            # Update basic info
            traffic['last_seen'] = now
            traffic['packets'].append(now)
            traffic['bytes_sent'] += packet_dict.get('length', 64)
            
            # Track packet size
            traffic['packet_sizes'].append(packet_dict.get('length', 64))
            
            # Track destination ports (for port scan detection)
            dport = packet_dict.get('dport', 0)
            if dport:
                traffic['dst_ports'].add(dport)
            
            # Track destination IPs
            dst_ip = packet_dict.get('dst', '')
            if dst_ip:
                traffic['dst_ips'].add(dst_ip)
            
            # Protocol distribution
            proto = packet_dict.get('proto', 'unknown')
            traffic['protocols'][proto] += 1
            
            # TCP flags analysis
            flags = packet_dict.get('flags', '')
            if flags:
                traffic['tcp_flags'][flags] += 1
                # Track SYN-only (connection attempts)
                if flags == 'S':
                    traffic['connection_attempts'] += 1
            
            # DNS query detection (port 53)
            if dport == 53 or proto == 'dns':
                traffic['dns_queries'].append(now)
            
            # ICMP detection
            if proto == 'icmp':
                traffic['icmp_count'] += 1
            
            # Global packet times for rate calculation
            self.global_packet_times.append(now)
            
            return self._compute_features(src_ip)
    
    def _compute_features(self, src_ip):
        """Compute current feature values for an IP"""
        traffic = self.ip_traffic[src_ip]
        now = time.time()
        window_start = now - self.window_size
        
        # Filter packets within window
        recent_packets = [t for t in traffic['packets'] if t > window_start]
        
        features = {
            'src_ip': src_ip,
            'timestamp': now,
            
            # Feature 1: Packet rate (packets/second)
            'packet_rate': len(recent_packets) / self.window_size,
            
            # Feature 2: Port diversity (unique destination ports)
            'port_diversity': len(traffic['dst_ports']),
            
            # Feature 3: Packet size - average
            'avg_packet_size': sum(traffic['packet_sizes']) / len(traffic['packet_sizes']) if traffic['packet_sizes'] else 64,
            
            # Feature 4: Packet size - min
            'min_packet_size': min(traffic['packet_sizes']) if traffic['packet_sizes'] else 64,
            
            # Feature 5: Packet size - max  
            'max_packet_size': max(traffic['packet_sizes']) if traffic['packet_sizes'] else 64,
            
            # Feature 6: Protocol distribution (as dict)
            'protocols': dict(traffic['protocols']),
            
            # Feature 7: TCP flags distribution
            'tcp_flags': dict(traffic['tcp_flags']),
            
            # Feature 8: Connection attempt rate
            'connection_rate': traffic['connection_attempts'] / max(1, (now - traffic['first_seen'])),
            
            # Feature 9: DNS query rate
            'dns_query_rate': len([t for t in traffic['dns_queries'] if t > window_start]) / self.window_size,
            
            # Feature 10: ICMP volume
            'icmp_count': traffic['icmp_count'],
            
            # Feature 11: Unique destination IPs
            'unique_dst_ips': len(traffic['dst_ips']),
            
            # Feature 12: Bytes per second
            'bytes_per_second': traffic['bytes_sent'] / max(1, now - traffic['first_seen']),
            
            # Feature 13: Active time
            'active_time': now - traffic['first_seen'] if traffic['first_seen'] else 0
        }
        
        return features
    
    def get_all_features(self):
        """Get features for all tracked IPs"""
        with self.lock:
            features = {}
            for src_ip in self.ip_traffic:
                features[src_ip] = self._compute_features(src_ip)
            return features
    
    def get_ip_features(self, src_ip):
        """Get features for a specific IP"""
        with self.lock:
            if src_ip in self.ip_traffic:
                return self._compute_features(src_ip)
            return None
    
    def reset_ip(self, src_ip):
        """Reset tracking for an IP (after rule generation)"""
        with self.lock:
            if src_ip in self.ip_traffic:
                # Keep first_seen but reset recent activity
                first_seen = self.ip_traffic[src_ip]['first_seen']
                self.ip_traffic[src_ip] = self.ip_traffic[src_ip].__class__(first_seen=first_seen)
    
    def clear_old_entries(self, max_age_seconds=300):
        """Remove IPs with no recent activity"""
        with self.lock:
            now = time.time()
            to_remove = []
            for src_ip, traffic in self.ip_traffic.items():
                if traffic['last_seen'] and (now - traffic['last_seen']) > max_age_seconds:
                    to_remove.append(src_ip)
            for ip in to_remove:
                del self.ip_traffic[ip]


class FeatureVector:
    """Represents a feature vector for an IP with anomaly scoring"""
    
    # Lower thresholds for easier detection in demo mode
    THRESHOLDS = {
        'port_scan': {
            'port_diversity': 10,      # 10+ unique ports in window (was 20)
            'connection_rate': 5,     # 5+ connections/second (was 10)
        },
        'syn_flood': {
            'connection_rate': 20,     # 20+ SYN packets/second (was 50)
            'packet_rate': 50,        # 50+ packets/second (was 100)
        },
        'ddos': {
            'packet_rate': 50,        # 50+ packets/second (was 200)
            'unique_dst_ips': 20,     # 20+ unique destinations (was 50)
        },
        'dns_amplification': {
            'dns_query_rate': 5,      # 5+ DNS queries/second (was 10)
            'avg_packet_size': 300,   # Large response packets (was 500)
        },
        'icmp_flood': {
            'icmp_count': 20,        # 20+ ICMP in window (was 50)
            'packet_rate': 15,       # 15+ packets/second (was 30)
        }
    }
    
    def __init__(self, features):
        self.features = features
        self.anomaly_scores = {}
        self.anomaly_types = []
    
    def calculate_anomaly_scores(self):
        """Calculate anomaly scores based on thresholds"""
        scores = {}
        
        # Port Scan Detection
        if self.features['port_diversity'] > self.THRESHOLDS['port_scan']['port_diversity']:
            score = min(1.0, self.features['port_diversity'] / (self.THRESHOLDS['port_scan']['port_diversity'] * 2))
            scores['port_scan'] = score
            if score > 0.5:
                self.anomaly_types.append('port_scan')
        
        # SYN Flood Detection
        if self.features['connection_rate'] > self.THRESHOLDS['syn_flood']['connection_rate']:
            score = min(1.0, self.features['connection_rate'] / (self.THRESHOLDS['syn_flood']['connection_rate'] * 2))
            scores['syn_flood'] = score
            if score > 0.5:
                self.anomaly_types.append('syn_flood')
        
        # DDoS Detection
        if self.features['packet_rate'] > self.THRESHOLDS['ddos']['packet_rate']:
            score = min(1.0, self.features['packet_rate'] / (self.THRESHOLDS['ddos']['packet_rate'] * 2))
            scores['ddos'] = score
            if score > 0.5:
                self.anomaly_types.append('ddos')
        
        # DNS Amplification
        if self.features['dns_query_rate'] > self.THRESHOLDS['dns_amplification']['dns_query_rate']:
            score = min(1.0, self.features['dns_query_rate'] / (self.THRESHOLDS['dns_amplification']['dns_query_rate'] * 2))
            scores['dns_amplification'] = score
            if score > 0.5:
                self.anomaly_types.append('dns_amplification')
        
        # ICMP Flood
        if self.features['icmp_count'] > self.THRESHOLDS['icmp_flood']['icmp_count']:
            score = min(1.0, self.features['icmp_count'] / (self.THRESHOLDS['icmp_flood']['icmp_count'] * 2))
            scores['icmp_flood'] = score
            if score > 0.5:
                self.anomaly_types.append('icmp_flood')
        
        self.anomaly_scores = scores
        return scores
    
    def get_max_score(self):
        """Get the highest anomaly score"""
        if not self.anomaly_scores:
            self.calculate_anomaly_scores()
        return max(self.anomaly_scores.values()) if self.anomaly_scores else 0.0
    
    def get_primary_anomaly(self):
        """Get the primary anomaly type"""
        if not self.anomaly_scores:
            self.calculate_anomaly_scores()
        if not self.anomaly_scores:
            return None
        return max(self.anomaly_scores, key=self.anomaly_scores.get)
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'src_ip': self.features['src_ip'],
            'timestamp': self.features['timestamp'],
            'features': {
                'packet_rate': round(self.features['packet_rate'], 2),
                'port_diversity': self.features['port_diversity'],
                'avg_packet_size': round(self.features['avg_packet_size'], 2),
                'connection_rate': round(self.features['connection_rate'], 2),
                'unique_dst_ips': self.features['unique_dst_ips'],
                'bytes_per_second': round(self.features['bytes_per_second'], 2)
            },
            'anomaly_scores': {k: round(v, 3) for k, v in self.anomaly_scores.items()},
            'anomaly_types': self.anomaly_types,
            'max_score': round(self.get_max_score(), 3)
        }


# Test function
if __name__ == '__main__':
    extractor = TrafficFeatureExtractor(window_size_seconds=10)
    
    # Simulate some packets
    test_packets = [
        {'src': '192.168.1.100', 'dst': '10.0.0.1', 'proto': 'tcp', 'sport': 12345, 'dport': 80, 'flags': 'S', 'length': 64},
        {'src': '192.168.1.100', 'dst': '10.0.0.2', 'proto': 'tcp', 'sport': 12346, 'dport': 443, 'flags': 'S', 'length': 64},
        {'src': '192.168.1.100', 'dst': '10.0.0.3', 'proto': 'tcp', 'sport': 12347, 'dport': 22, 'flags': 'S', 'length': 64},
    ]
    
    for pkt in test_packets:
        time.sleep(0.1)
        extractor.extract_features(pkt)
    
    features = extractor.get_all_features()
    print("Features:", features)
    
    # Test anomaly detection
    for ip, feat in features.items():
        fv = FeatureVector(feat)
        fv.calculate_anomaly_scores()
        print(f"IP: {ip}, Anomaly: {fv.to_dict()}")

