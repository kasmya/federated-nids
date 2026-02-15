#!/usr/bin/env python3
"""
Anomaly Detector - Layer 2: The Brain
ML/Anomaly Detection for Network Intrusion Detection
Uses threshold-based detection with adaptive baselines
"""

import time
import threading
import logging
from datetime import datetime
from collections import defaultdict, deque
import hashlib
import json

from .traffic_analyzer import TrafficFeatureExtractor, FeatureVector
from .baselines import AdaptiveBaseline, IPBaselineManager

logger = logging.getLogger(__name__)


class AnomalyType:
    """Enumeration of anomaly types"""
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    DDOS = "potential_ddos"
    DNS_AMPLIFICATION = "dns_amplification"
    ICMP_FLOOD = "icmp_flood"
    UNUSUAL_SIZE = "unusual_packet_size"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"


class Anomaly:
    """Represents a detected anomaly"""
    
    def __init__(self, src_ip, anomaly_type, score, features, details=None):
        self.id = self._generate_id(src_ip, anomaly_type)
        self.src_ip = src_ip
        self.anomaly_type = anomaly_type
        self.score = score
        self.features = features
        self.details = details or {}
        self.timestamp = datetime.now()
        self.severity = self._calculate_severity(score)
        self.rule_generated = False
        self.rule_id = None
    
    def _generate_id(self, src_ip, anomaly_type):
        """Generate unique ID for anomaly"""
        data = f"{src_ip}:{anomaly_type}:{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _calculate_severity(self, score):
        """Calculate severity from score"""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.5:
            return "medium"
        else:
            return "low"
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'src_ip': self.src_ip,
            'anomaly_type': self.anomaly_type,
            'score': round(self.score, 3),
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'features': {
                'packet_rate': round(self.features.get('packet_rate', 0), 2),
                'port_diversity': self.features.get('port_diversity', 0),
                'connection_rate': round(self.features.get('connection_rate', 0), 2),
                'unique_dst_ips': self.features.get('unique_dst_ips', 0),
            },
            'details': self.details,
            'rule_generated': self.rule_generated,
            'rule_id': self.rule_id
        }


class SimpleAnomalyDetector:
    """
    Layer 2: The Brain
    Simple threshold-based anomaly detection with adaptive baselines.
    Designed to work without heavy ML frameworks.
    """
    
    def __init__(self, window_size_seconds=10, detection_threshold=0.5):
        self.window_size = window_size_seconds
        self.detection_threshold = detection_threshold
        
        # Feature extraction
        self.feature_extractor = TrafficFeatureExtractor(window_size_seconds)
        
        # Baseline management (per-IP)
        self.ip_baselines = IPBaselineManager()
        
        # Detection state
        self.recent_anomalies = deque(maxlen=100)
        self.anomaly_history = defaultdict(lambda: deque(maxlen=50))
        self.active_anomalies = {}  # src_ip -> Anomaly
        
        # Detection callbacks
        self.on_anomaly_detected = None
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'total_packets_processed': 0,
            'total_anomalies_detected': 0,
            'anomaly_types_detected': defaultdict(int),
            'rules_generated': 0
        }
        
        # Configuration
        self.enabled = True
        self.min_packets_before_detection = 3
        
        logger.info("SimpleAnomalyDetector initialized")
    
    def set_anomaly_callback(self, callback):
        """Set callback function to be called when anomaly is detected"""
        self.on_anomaly_detected = callback
    
    def process_packet(self, packet_dict):
        """
        Process a packet and check for anomalies.
        packet_dict should contain: src, dst, proto, sport, dport, flags, length
        """
        if not self.enabled:
            return None
        
        with self.lock:
            self.stats['total_packets_processed'] += 1
            
            # Extract features
            features = self.feature_extractor.extract_features(packet_dict)
            
            # Get IP-specific baseline
            src_ip = packet_dict.get('src', 'unknown')
            if src_ip == 'unknown':
                return None
            
            # Update baseline (in learning mode or detection mode)
            baseline = self.ip_baselines.get_or_create_baseline(src_ip)
            baseline.update_from_features(features)
            
            # Create feature vector and calculate anomaly scores
            fv = FeatureVector(features)
            fv.calculate_anomaly_scores()
            
            # Check if any anomaly threshold is exceeded
            max_score = fv.get_max_score()
            if max_score >= self.detection_threshold:
                anomaly_type = fv.get_primary_anomaly()
                
                # Check if this is a new or escalating anomaly
                anomaly = self._create_or_update_anomaly(
                    src_ip, anomaly_type, max_score, features
                )
                
                if anomaly:
                    self.stats['total_anomalies_detected'] += 1
                    self.stats['anomaly_types_detected'][anomaly_type] += 1
                    
                    # Trigger callback
                    if self.on_anomaly_detected:
                        try:
                            self.on_anomaly_detected(anomaly)
                        except Exception as e:
                            logger.error(f"Error in anomaly callback: {e}")
                    
                    return anomaly
            
            # Update baseline last update time
            baseline.last_update = time.time()
            
            return None
    
    def _create_or_update_anomaly(self, src_ip, anomaly_type, score, features):
        """Create new anomaly or update existing one"""
        current_time = time.time()
        
        # Check if we already have an active anomaly for this IP/type
        key = f"{src_ip}:{anomaly_type}"
        
        if key in self.active_anomalies:
            existing = self.active_anomalies[key]
            # Update if score increased significantly
            if score > existing.score + 0.1:
                existing.score = score
                existing.features = features
                existing.timestamp = datetime.now()
                return existing
            return None
        
        # Create new anomaly
        details = self._generate_anomaly_details(anomaly_type, features)
        
        anomaly = Anomaly(src_ip, anomaly_type, score, features, details)
        
        self.active_anomalies[key] = anomaly
        self.recent_anomalies.append(anomaly)
        self.anomaly_history[src_ip].append(anomaly)
        
        return anomaly
    
    def _generate_anomaly_details(self, anomaly_type, features):
        """Generate detailed information about the anomaly"""
        details = {}
        
        if anomaly_type == AnomalyType.PORT_SCAN:
            details['description'] = "Unusual number of unique ports contacted"
            details['ports_scanned'] = features.get('port_diversity', 0)
            details['recommendation'] = f"Block source IP {features.get('src_ip')} or monitor for suspicious activity"
        
        elif anomaly_type == AnomalyType.SYN_FLOOD:
            details['description'] = "High rate of SYN packets detected"
            details['syn_rate'] = features.get('connection_rate', 0)
            details['recommendation'] = "Possible SYN flood attack - consider rate limiting"
        
        elif anomaly_type == AnomalyType.DDOS:
            details['description'] = "High volume of traffic from single source"
            details['packet_rate'] = features.get('packet_rate', 0)
            details['unique_destinations'] = features.get('unique_dst_ips', 0)
            details['recommendation'] = "Possible DDoS attack - block source IP"
        
        elif anomaly_type == AnomalyType.ICMP_FLOOD:
            details['description'] = "High volume of ICMP packets"
            details['icmp_count'] = features.get('icmp_count', 0)
            details['recommendation'] = "Possible ICMP flood - consider blocking ICMP"
        
        elif anomaly_type == AnomalyType.DNS_AMPLIFICATION:
            details['description'] = "High rate of DNS queries"
            details['dns_rate'] = features.get('dns_query_rate', 0)
            details['recommendation'] = "Possible DNS amplification attack"
        
        return details
    
    def get_recent_anomalies(self, limit=20):
        """Get recent anomalies"""
        with self.lock:
            anomalies = list(self.recent_anomalies)
            return [a.to_dict() for a in anomalies[-limit:]]
    
    def get_anomalies_for_ip(self, src_ip):
        """Get all anomalies for a specific IP"""
        with self.lock:
            if src_ip in self.anomaly_history:
                return [a.to_dict() for a in self.anomaly_history[src_ip]]
            return []
    
    def get_active_anomalies(self):
        """Get currently active anomalies"""
        with self.lock:
            return {k: v.to_dict() for k, v in self.active_anomalies.items()}
    
    def clear_anomaly(self, src_ip, anomaly_type=None):
        """Clear anomaly for an IP (after rule generation)"""
        with self.lock:
            if anomaly_type:
                key = f"{src_ip}:{anomaly_type}"
                if key in self.active_anomalies:
                    del self.active_anomalies[key]
            else:
                # Clear all anomalies for IP
                keys_to_remove = [k for k in self.active_anomalies.keys() if k.startswith(f"{src_ip}:")]
                for key in keys_to_remove:
                    del self.active_anomalies[key]
    
    def get_statistics(self):
        """Get detection statistics"""
        with self.lock:
            return {
                'total_packets': self.stats['total_packets_processed'],
                'total_anomalies': self.stats['total_anomalies_detected'],
                'anomaly_types': dict(self.stats['anomaly_types_detected']),
                'active_anomalies': len(self.active_anomalies),
                'rules_generated': self.stats['rules_generated'],
                'tracked_ips': len(self.ip_baselines.baselines),
                'enabled': self.enabled
            }
    
    def enable(self):
        """Enable anomaly detection"""
        self.enabled = True
        logger.info("Anomaly detection enabled")
    
    def disable(self):
        """Disable anomaly detection"""
        self.enabled = False
        logger.info("Anomaly detection disabled")
    
    def reset(self):
        """Reset detector state"""
        with self.lock:
            self.feature_extractor = TrafficFeatureExtractor(self.window_size)
            self.ip_baselines = IPBaselineManager()
            self.recent_anomalies.clear()
            self.anomaly_history.clear()
            self.active_anomalies.clear()
            self.stats = {
                'total_packets_processed': 0,
                'total_anomalies_detected': 0,
                'anomaly_types_detected': defaultdict(int),
                'rules_generated': 0
            }
            logger.info("Anomaly detector reset")


# Factory function for creating detector
def create_anomaly_detector(config=None):
    """Create and configure an anomaly detector"""
    config = config or {}
    
    detector = SimpleAnomalyDetector(
        window_size_seconds=config.get('window_size', 10),
        detection_threshold=config.get('threshold', 0.5)
    )
    
    return detector


if __name__ == '__main__':
    # Test the anomaly detector
    detector = SimpleAnomalyDetector()
    
    # Simulate packets (port scan)
    print("Simulating port scan...")
    for port in range(1, 30):
        packet = {
            'src': '192.168.1.100',
            'dst': f'10.0.0.{port}',
            'proto': 'tcp',
            'sport': 12345 + port,
            'dport': port,
            'flags': 'S',
            'length': 64
        }
        detector.process_packet(packet)
        time.sleep(0.01)
    
    print("\nRecent anomalies:")
    for a in detector.get_recent_anomalies():
        print(f"  {a['anomaly_type']}: {a['src_ip']} (score: {a['score']})")
    
    print("\nStatistics:", detector.get_statistics())

