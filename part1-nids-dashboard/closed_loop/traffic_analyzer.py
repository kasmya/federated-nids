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
        """Extract features from a packet dictionary."""
        with self.lock:
            src_ip = packet_dict.get('src', 'unknown')
            now = time.time()
            
            traffic = self.ip_traffic[src_ip]
            
            if traffic['first_seen'] is None:
                traffic['first_seen'] = now
            
            traffic['last_seen'] = now
            traffic['packets'].append(now)
            traffic['bytes_sent'] += packet_dict.get('length', 64)
            traffic['packet_sizes'].append(packet_dict.get('length', 64))
            
            dport = packet_dict.get('dport', 0)
            if dport:
                traffic['dst_ports'].add(dport)
            
            dst_ip = packet_dict.get('dst', '')
            if dst_ip:
                traffic['dst_ips'].add(dst_ip)
            
            proto = packet_dict.get('proto', 'unknown')
            traffic['protocols'][proto] += 1
            
            flags = packet_dict.get('flags', '')
            if flags:
                traffic['tcp_flags'][flags] += 1
                if flags == 'S':
                    traffic['connection_attempts'] += 1
            
            if dport == 53 or proto == 'dns':
                traffic['dns_queries'].append(now)
            
            if proto == 'icmp':
                traffic['icmp_count'] += 1
            
            self.global_packet_times.append(now)
            
            return self._compute_features(src_ip)
    
    def _compute_features(self, src_ip):
        """Compute current feature values for an IP"""
        traffic = self.ip_traffic[src_ip]
        now = time.time()
        window_start = now - self.window_size
        
        recent_packets = [t for t in traffic['packets'] if t > window_start]
        
        features = {
            'src_ip': src_ip,
            'timestamp': now,
            'packet_rate': len(recent_packets) / self.window_size,
            'port_diversity': len(traffic['dst_ports']),
            'avg_packet_size': sum(traffic['packet_sizes']) / len(traffic['packet_sizes']) if traffic['packet_sizes'] else 64,
            'min_packet_size': min(traffic['packet_sizes']) if traffic['packet_sizes'] else 64,
            'max_packet_size': max(traffic['packet_sizes']) if traffic['packet_sizes'] else 64,
            'protocols': dict(traffic['protocols']),
            'tcp_flags': dict(traffic['tcp_flags']),
            'connection_rate': traffic['connection_attempts'] / max(1, (now - traffic['first_seen'])),
            'dns_query_rate': len([t for t in traffic['dns_queries'] if t > window_start]) / self.window_size,
            'icmp_count': traffic['icmp_count'],
            'unique_dst_ips': len(traffic['dst_ips']),
            'bytes_per_second': traffic['bytes_sent'] / max(1, now - traffic['first_seen']),
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
        """Reset tracking for an IP"""
        with self.lock:
            if src_ip in self.ip_traffic:
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
    
    DEFAULT_THRESHOLDS = {
        'port_scan': {
            'port_diversity': 50,
            'connection_rate': 8,
        },
        'syn_flood': {
            'connection_rate': 15,
            'packet_rate': 25,
        },
        'ddos': {
            'packet_rate': 30,
            'unique_dst_ips': 15,
        },
        'dns_amplification': {
            'dns_query_rate': 5,
            'avg_packet_size': 300,
        },
        'icmp_flood': {
            'icmp_count': 20,
            'packet_rate': 20,
        }
    }
    
    _learned_thresholds = {}
    _use_learned = False
    _adaptive_stats = {}
    _use_adaptive = False
    _adaptive_multiplier = 2.0
    
    def __init__(self, features):
        self.features = features
        self.anomaly_scores = {}
        self.anomaly_types = []
    
    @classmethod
    def set_learned_thresholds(cls, thresholds):
        cls._learned_thresholds = thresholds
        cls._use_learned = True
        logger.info(f"Using learned thresholds: {thresholds}")
    
    @classmethod
    def use_default_thresholds(cls):
        cls._use_learned = False
        cls._learned_thresholds = {}
    
    @classmethod
    def get_effective_thresholds(cls):
        if cls._use_learned and cls._learned_thresholds:
            return cls._learned_thresholds
        return cls.DEFAULT_THRESHOLDS
    
    def _get_threshold(self, anomaly_type, feature_name):
        if self._use_learned and self._learned_thresholds:
            if anomaly_type in self._learned_thresholds:
                if feature_name in self._learned_thresholds[anomaly_type]:
                    return self._learned_thresholds[anomaly_type][feature_name]
        
        if anomaly_type in self.DEFAULT_THRESHOLDS:
            if feature_name in self.DEFAULT_THRESHOLDS[anomaly_type]:
                return self.DEFAULT_THRESHOLDS[anomaly_type][feature_name]
        
        return 1
    
    def calculate_anomaly_scores(self):
        scores = {}
        
        # Port Scan Detection
        port_scan_threshold = self._get_threshold('port_scan', 'port_diversity')
        adaptive_threshold = self._get_adaptive_threshold('port_scan', 'port_diversity')
        if adaptive_threshold is not None:
            port_scan_threshold = adaptive_threshold
        if self.features.get('port_diversity', 0) > port_scan_threshold:
            score = min(1.0, self.features.get('port_diversity', 0) / (port_scan_threshold * 2))
            scores['port_scan'] = score
            if score > 0.5:
                self.anomaly_types.append('port_scan')
        
        # SYN Flood Detection
        syn_threshold = self._get_threshold('syn_flood', 'connection_rate')
        adaptive_threshold = self._get_adaptive_threshold('syn_flood', 'connection_rate')
        if adaptive_threshold is not None:
            syn_threshold = adaptive_threshold
        if self.features.get('connection_rate', 0) > syn_threshold:
            score = min(1.0, self.features.get('connection_rate', 0) / (syn_threshold * 2))
            scores['syn_flood'] = score
            if score > 0.5:
                self.anomaly_types.append('syn_flood')
        
        # DDoS Detection
        ddos_threshold = self._get_threshold('ddos', 'packet_rate')
        adaptive_threshold = self._get_adaptive_threshold('ddos', 'packet_rate')
        if adaptive_threshold is not None:
            ddos_threshold = adaptive_threshold
        if self.features.get('packet_rate', 0) > ddos_threshold:
            score = min(1.0, self.features.get('packet_rate', 0) / (ddos_threshold * 2))
            scores['ddos'] = score
            if score > 0.5:
                self.anomaly_types.append('ddos')
        
        # DNS Amplification
        dns_threshold = self._get_threshold('dns_amplification', 'dns_query_rate')
        if self.features.get('dns_query_rate', 0) > dns_threshold:
            score = min(1.0, self.features.get('dns_query_rate', 0) / (dns_threshold * 2))
            scores['dns_amplification'] = score
            if score > 0.5:
                self.anomaly_types.append('dns_amplification')
        
        # ICMP Flood
        icmp_threshold = self._get_threshold('icmp_flood', 'icmp_count')
        adaptive_threshold = self._get_adaptive_threshold('icmp_flood', 'icmp_count')
        if adaptive_threshold is not None:
            icmp_threshold = adaptive_threshold
        if self.features.get('icmp_count', 0) > icmp_threshold:
            score = min(1.0, self.features.get('icmp_count', 0) / (icmp_threshold * 2))
            scores['icmp_flood'] = score
            if score > 0.5:
                self.anomaly_types.append('icmp_flood')
        
        self.anomaly_scores = scores
        return scores
    
    def get_max_score(self):
        if not self.anomaly_scores:
            self.calculate_anomaly_scores()
        return max(self.anomaly_scores.values()) if self.anomaly_scores else 0.0
    
    def get_primary_anomaly(self):
        if not self.anomaly_scores:
            self.calculate_anomaly_scores()
        if not self.anomaly_scores:
            return None
        return max(self.anomaly_scores, key=self.anomaly_scores.get)
    
    def to_dict(self):
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
    
    @classmethod
    def enable_adaptive_thresholds(cls, multiplier=2.0):
        cls._use_adaptive = True
        cls._adaptive_multiplier = multiplier
        cls._adaptive_stats = {}
        logger.info(f"Adaptive thresholds enabled (multiplier: {multiplier})")
    
    @classmethod
    def disable_adaptive_thresholds(cls):
        cls._use_adaptive = False
        logger.info("Adaptive thresholds disabled")
    
    @classmethod
    def compute_adaptive_thresholds(cls, all_features):
        """Compute adaptive thresholds based on statistical distribution."""
        if not cls._use_adaptive:
            return
        
        feature_values = {
            'port_diversity': [],
            'connection_rate': [],
            'packet_rate': [],
            'unique_dst_ips': [],
            'icmp_count': []
        }
        
        for src_ip, features in all_features.items():
            feature_values['port_diversity'].append(features.get('port_diversity', 0))
            feature_values['connection_rate'].append(features.get('connection_rate', 0))
            feature_values['packet_rate'].append(features.get('packet_rate', 0))
            feature_values['unique_dst_ips'].append(features.get('unique_dst_ips', 0))
            feature_values['icmp_count'].append(features.get('icmp_count', 0))
        
        cls._adaptive_stats = {}
        
        for feature_name, values in feature_values.items():
            if len(values) < 2:
                continue
            
            mean_val = sum(values) / len(values)
            variance = sum((x - mean_val) ** 2 for x in values) / len(values)
            std_val = variance ** 0.5
            
            # FIX: When std is near 0 (uniform traffic), use mean * 1.5 instead
            # This prevents false positives when all IPs have similar patterns
            if std_val < 0.01:
                threshold = mean_val * 1.5
            else:
                threshold = mean_val + (cls._adaptive_multiplier * std_val)
            
            cls._adaptive_stats[feature_name] = {
                'mean': mean_val,
                'std': std_val,
                'threshold': threshold,
                'min': min(values),
                'max': max(values),
                'count': len(values)
            }
        
        logger.info(f"Computed adaptive thresholds: {cls._adaptive_stats}")
    
    def _get_adaptive_threshold(self, anomaly_type, feature_name):
        if not self._use_adaptive or not self._adaptive_stats:
            return None
        
        feature_map = {
            'port_scan': 'port_diversity',
            'syn_flood': 'connection_rate',
            'ddos': 'packet_rate',
            'icmp_flood': 'icmp_count'
        }
        
        primary_feature = feature_map.get(anomaly_type, feature_name)
        
        if primary_feature in self._adaptive_stats:
            return self._adaptive_stats[primary_feature]['threshold']
        
        return None


if __name__ == '__main__':
    extractor = TrafficFeatureExtractor(window_size_seconds=10)
    
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
    
    for ip, feat in features.items():
        fv = FeatureVector(feat)
        fv.calculate_anomaly_scores()
        print(f"IP: {ip}, Anomaly: {fv.to_dict()}")
