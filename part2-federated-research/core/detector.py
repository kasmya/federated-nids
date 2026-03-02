#!/usr/bin/env python3
"""
Minimal Anomaly Detector - Layer 2
Detects network attacks based on traffic features
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class AttackType(Enum):
    """Attack types we can detect"""
    NORMAL = "normal"
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    DDOS = "ddos"
    ICMP_FLOOD = "icmp_flood"


@dataclass
class Anomaly:
    """Represents a detected anomaly"""
    attack_type: AttackType
    src_ip: str
    score: float  # 0-1 confidence
    features: Dict[str, float]


class SimpleDetector:
    """Minimal anomaly detector using threshold-based detection"""
    
    # Detection thresholds - adjusted for realistic detection
    THRESHOLDS = {
        'port_scan': {'port_diversity': 20, 'connection_rate': 5},  # Lowered from 50, 8
        'syn_flood': {'connection_rate': 8, 'packet_rate': 15},       # Lowered from 15, 25
        'ddos': {'packet_rate': 30, 'unique_dst_ips': 15},
        'icmp_flood': {'icmp_count': 20, 'packet_rate': 20},
    }
    
    def __init__(self, detection_threshold: float = 0.5):
        self.detection_threshold = detection_threshold
        self.baselines: Dict[str, Dict] = {}  # IP -> feature values
        self.detections: List[Anomaly] = []
    
    def process_packet(self, packet: Dict) -> Optional[Anomaly]:
        """Process a packet and return anomaly if detected"""
        src_ip = packet.get('src', 'unknown')
        
        # Initialize baseline for new IPs
        if src_ip not in self.baselines:
            self.baselines[src_ip] = {
                'ports': set(), 'packets': 0, 'connections': 0,
                'dst_ips': set(), 'icmp_count': 0, 'bytes': 0
            }
        
        # Update features
        bl = self.baselines[src_ip]
        bl['ports'].add(packet.get('dport', 0))
        bl['packets'] += 1
        bl['dst_ips'].add(packet.get('dst', ''))
        bl['bytes'] += packet.get('length', 64)
        
        if packet.get('flags') == 'S':
            bl['connections'] += 1
        if packet.get('proto') == 'icmp':
            bl['icmp_count'] += 1
        
        # Check thresholds
        return self._detect(src_ip, bl)
    
    def _detect(self, ip: str, features: Dict) -> Optional[Anomaly]:
        """Check if features indicate an attack"""
        port_div = len(features['ports'])
        conn_rate = features['connections'] / max(features['packets'], 1) * 10
        packet_rate = features['packets']  # Simplified
        icmp_count = features['icmp_count']
        unique_dst = len(features['dst_ips'])
        
        # Port scan detection
        if port_div > self.THRESHOLDS['port_scan']['port_diversity']:
            return Anomaly(AttackType.PORT_SCAN, ip, 0.8, {'port_diversity': port_div})
        
        # SYN flood detection
        if conn_rate > self.THRESHOLDS['syn_flood']['connection_rate']:
            return Anomaly(AttackType.SYN_FLOOD, ip, 0.9, {'connection_rate': conn_rate})
        
        # DDoS detection
        if packet_rate > self.THRESHOLDS['ddos']['packet_rate'] and unique_dst > 15:
            return Anomaly(AttackType.DDOS, ip, 0.85, {'packet_rate': packet_rate})
        
        # ICMP flood detection
        if icmp_count > self.THRESHOLDS['icmp_flood']['icmp_count']:
            return Anomaly(AttackType.ICMP_FLOOD, ip, 0.8, {'icmp_count': icmp_count})
        
        return None
    
    def get_detections(self) -> List[Anomaly]:
        return self.detections
