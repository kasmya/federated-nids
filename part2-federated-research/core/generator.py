#!/usr/bin/env python3
"""
Minimal Rule Generator - Layer 3
Creates detection rules from detected anomalies
"""

from typing import Dict, List
from dataclasses import dataclass
import hashlib


@dataclass
class DetectionRule:
    """A detection rule created from an anomaly"""
    rule_id: str
    rule_string: str
    attack_type: str
    src_ip: str
    score: float


class SimpleRuleGenerator:
    """Minimal rule generator - creates rules from anomalies"""
    
    def __init__(self):
        self.rules: List[DetectionRule] = []
        self.rule_counter = 0
    
    def generate_rule(self, anomaly) -> DetectionRule:
        """Create a detection rule from an anomaly"""
        self.rule_counter += 1
        
        # Create Snort-style rule (avoid nested quotes)
        msg = anomaly.attack_type.value.upper() + "_DETECTED"
        rule_string = "alert tcp " + anomaly.src_ip + " any -> any any (msg:\"" + msg + "\"; sid:" + str(1000 + self.rule_counter) + ";)"
        
        rule = DetectionRule(
            rule_id=f"rule_{self.rule_counter}",
            rule_string=rule_string,
            attack_type=anomaly.attack_type.value,
            src_ip=anomaly.src_ip,
            score=anomaly.score
        )
        
        self.rules.append(rule)
        return rule
    
    def get_rules(self) -> List[DetectionRule]:
        return self.rules
    
    def get_rules_dict(self) -> List[Dict]:
        """Get rules as dictionaries for federation"""
        return [
            {
                'rule_string': r.rule_string,
                'anomaly_type': r.attack_type,
                'src_ip': r.src_ip,
                'score': r.score
            }
            for r in self.rules
        ]
