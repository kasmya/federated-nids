#!/usr/bin/env python3
"""
Minimal Closed-Loop NIDS
Combines detection + rule generation
"""

from typing import List, Optional
from .detector import SimpleDetector, Anomaly
from .generator import SimpleRuleGenerator, DetectionRule


class ClosedLoopNIDS:
    """Minimal NIDS with closed-loop learning"""
    
    def __init__(self, detection_threshold: float = 0.5):
        self.detector = SimpleDetector(detection_threshold)
        self.rule_generator = SimpleRuleGenerator()
        self.total_packets = 0
        self.total_anomalies = 0
        self.total_rules = 0
    
    def process_packet(self, packet: dict) -> Optional[Anomaly]:
        """Process packet through the closed loop"""
        self.total_packets += 1
        
        # Layer 2: Detect anomalies
        anomaly = self.detector.process_packet(packet)
        
        if anomaly:
            self.total_anomalies += 1
            
            # Layer 3: Generate rules
            rule = self.rule_generator.generate_rule(anomaly)
            if rule:
                self.total_rules += 1
        
        return anomaly
    
    def get_status(self) -> dict:
        return {
            'packets_processed': self.total_packets,
            'anomalies_detected': self.total_anomalies,
            'rules_generated': self.total_rules,
        }
    
    def get_local_rules(self) -> List[DetectionRule]:
        return self.rule_generator.get_rules()
