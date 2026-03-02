#!/usr/bin/env python3
"""
Rule Generator - Layer 3: The Teacher
Auto-generates rules from detected anomalies
"""

import time
import threading
import logging
import hashlib
import os
from datetime import datetime
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


class AutoRule:
    """Represents an auto-generated rule"""
    
    RULE_FORMAT = "alert {proto} {srcip} {srcport} --> {dstip} {dstport} {msg}"
    
    def __init__(self, src_ip, anomaly_type, rule_proto='tcp', dst_port='any', 
                 message=None, score=0.0, parent_anomaly_id=None):
        self.id = self._generate_id(src_ip, anomaly_type)
        self.src_ip = src_ip
        self.anomaly_type = anomaly_type
        self.rule_proto = rule_proto
        self.dst_port = dst_port
        self.message = message or f"AUTO_{anomaly_type.upper()}_{self.id[:8]}"
        self.score = score
        self.parent_anomaly_id = parent_anomaly_id
        
        # Rule metadata
        self.created_at = datetime.now()
        self.enabled = True
        self.hit_count = 0
        self.last_hit = None
        
        # Validation
        self.validated = False
        self.validation_error = None
    
    def _generate_id(self, src_ip, anomaly_type):
        """Generate unique ID for rule"""
        data = f"{src_ip}:{anomaly_type}:{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def to_rule_string(self):
        """Convert to Snort-style rule string"""
        return self.RULE_FORMAT.format(
            proto=self.rule_proto,
            srcip=self.src_ip,
            srcport='any',
            dstip='any',
            dstport=self.dst_port,
            msg=self.message
        )
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'src_ip': self.src_ip,
            'anomaly_type': self.anomaly_type,
            'rule_proto': self.rule_proto,
            'dst_port': self.dst_port,
            'rule_string': self.to_rule_string(),
            'message': self.message,
            'score': round(self.score, 3),
            'created_at': self.created_at.isoformat(),
            'enabled': self.enabled,
            'hit_count': self.hit_count,
            'validated': self.validated
        }
    
    def matches_packet(self, pkt_src, pkt_proto, pkt_dport):
        """Check if a packet matches this rule"""
        if not self.enabled:
            return False
        
        # Check source IP
        if pkt_src != self.src_ip:
            return False
        
        # Check protocol
        if self.rule_proto != 'any' and pkt_proto != self.rule_proto:
            return False
        
        # Check destination port
        if self.dst_port != 'any':
            try:
                if int(pkt_dport) != int(self.dst_port):
                    return False
            except:
                pass
        
        return True


class RuleGenerator:
    """
    Layer 3: The Teacher
    Converts detected anomalies into actionable rules.
    """
    
    # Rule generation templates for different anomaly types
    RULE_TEMPLATES = {
        'port_scan': {
            'proto': 'tcp',
            'dst_port': 'any',
            'message_prefix': 'AUTO_PORT_SCAN'
        },
        'syn_flood': {
            'proto': 'tcp',
            'dst_port': 'any',  # Could be 80, 443 for web servers
            'message_prefix': 'AUTO_SYN_FLOOD'
        },
        'potential_ddos': {
            'proto': 'any',
            'dst_port': 'any',
            'message_prefix': 'AUTO_DDOS'
        },
        'icmp_flood': {
            'proto': 'icmp',
            'dst_port': 'any',
            'message_prefix': 'AUTO_ICMP_FLOOD'
        },
        'dns_amplification': {
            'proto': 'udp',
            'dst_port': 53,
            'message_prefix': 'AUTO_DNS_AMP'
        },
        'brute_force': {
            'proto': 'tcp',
            'dst_port': 'any',
            'message_prefix': 'AUTO_BRUTE_FORCE'
        }
    }
    
    def __init__(self, auto_rules_file='auto_rules.txt'):
        self.auto_rules_file = auto_rules_file
        self.auto_rules = {}  # id -> AutoRule
        self.rule_history = []  # All generated rules
        
        # Rule cache for quick lookup
        self.ip_rules = defaultdict(list)  # src_ip -> [rules]
        
        # Duplicate detection
        self.generated_rule_hashes = set()
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Callbacks
        self.on_rule_created = None
        self.on_rule_deployed = None
        
        # Statistics
        self.stats = {
            'total_rules_generated': 0,
            'total_duplicates_prevented': 0,
            'rules_deployed': 0,
            'rules_rejected': 0
        }
        
        # Load existing auto-rules
        self._load_rules()
        
        logger.info(f"RuleGenerator initialized with {len(self.auto_rules)} existing rules")
    
    def set_rule_callbacks(self, on_created=None, on_deployed=None):
        """Set callback functions"""
        self.on_rule_created = on_created
        self.on_rule_deployed = on_deployed
    
    def generate_rule(self, anomaly):
        """
        Generate a rule from an anomaly.
        Returns AutoRule if successful, None if duplicate or invalid.
        """
        with self.lock:
            # Check if we already have a rule for this IP/type
            existing = self._find_existing_rule(anomaly.src_ip, anomaly.anomaly_type)
            if existing:
                logger.info(f"Rule already exists for {anomaly.src_ip}:{anomaly.anomaly_type}")
                self.stats['total_duplicates_prevented'] += 1
                return None
            
            # Get template for anomaly type
            template = self.RULE_TEMPLATES.get(anomaly.anomaly_type, 
                                                self.RULE_TEMPLATES['port_scan'])
            
            # Determine destination port based on features
            dst_port = self._determine_dst_port(anomaly)
            
            # Create rule
            rule = AutoRule(
                src_ip=anomaly.src_ip,
                anomaly_type=anomaly.anomaly_type,
                rule_proto=template['proto'],
                dst_port=dst_port,
                message=f"{template['message_prefix']}_{anomaly.id[:8]}",
                score=anomaly.score,
                parent_anomaly_id=anomaly.id
            )
            
            # Validate rule
            if not self._validate_rule(rule):
                logger.warning(f"Rule validation failed: {rule.validation_error}")
                self.stats['rules_rejected'] += 1
                return None
            
            # Check for duplicate by content hash
            rule_hash = hashlib.md5(rule.to_rule_string().encode()).hexdigest()
            if rule_hash in self.generated_rule_hashes:
                logger.info("Duplicate rule detected by hash")
                self.stats['total_duplicates_prevented'] += 1
                return None
            
            # Add to rules
            self.auto_rules[rule.id] = rule
            self.ip_rules[rule.src_ip].append(rule)
            self.generated_rule_hashes.add(rule_hash)
            self.rule_history.append(rule)
            
            self.stats['total_rules_generated'] += 1
            
            # Save to file
            self._save_rule(rule)
            
            # Trigger callback
            if self.on_rule_created:
                try:
                    self.on_rule_created(rule)
                except Exception as e:
                    logger.error(f"Error in rule created callback: {e}")
            
            logger.info(f"Generated rule: {rule.to_rule_string()}")
            return rule
    
    def _determine_dst_port(self, anomaly):
        """Determine destination port from anomaly features"""
        features = anomaly.features
        anomaly_type = anomaly.anomaly_type
        
        if anomaly_type == 'port_scan':
            # Use the most common port or any
            return 'any'
        
        elif anomaly_type == 'syn_flood':
            # Could check which ports are being targeted
            return 'any'
        
        elif anomaly_type == 'dns_amplification':
            return 53
        
        else:
            return 'any'
    
    def _validate_rule(self, rule):
        """Validate a rule before deployment"""
        # Check source IP is valid
        if not rule.src_ip or rule.src_ip == 'unknown':
            rule.validation_error = "Invalid source IP"
            return False
        
        # Check IP format (basic validation)
        parts = rule.src_ip.split('.')
        if len(parts) != 4:
            rule.validation_error = "Invalid IP format"
            return False
        
        try:
            for part in parts:
                if int(part) > 255:
                    rule.validation_error = "Invalid IP octet"
                    return False
        except:
            rule.validation_error = "Invalid IP format"
            return False
        
        # Check protocol
        if rule.rule_proto not in ['tcp', 'udp', 'icmp', 'any']:
            rule.validation_error = "Invalid protocol"
            return False
        
        rule.validated = True
        return True
    
    def _find_existing_rule(self, src_ip, anomaly_type):
        """Find existing rule for IP and anomaly type"""
        if src_ip in self.ip_rules:
            for rule in self.ip_rules[src_ip]:
                if rule.anomaly_type == anomaly_type and rule.enabled:
                    return rule
        return None
    
    def get_rule(self, rule_id):
        """Get rule by ID"""
        with self.lock:
            return self.auto_rules.get(rule_id)
    
    def get_all_rules(self):
        """Get all auto-generated rules"""
        with self.lock:
            return [rule.to_dict() for rule in self.auto_rules.values()]
    
    def get_enabled_rules(self):
        """Get only enabled rules"""
        with self.lock:
            return [rule.to_dict() for rule in self.auto_rules.values() if rule.enabled]
    
    def get_rules_for_ip(self, src_ip):
        """Get all rules for an IP"""
        with self.lock:
            if src_ip in self.ip_rules:
                return [rule.to_dict() for rule in self.ip_rules[src_ip]]
            return []
    
    def enable_rule(self, rule_id):
        """Enable a rule"""
        with self.lock:
            if rule_id in self.auto_rules:
                self.auto_rules[rule_id].enabled = True
                self._save_all_rules()
                return True
            return False
    
    def disable_rule(self, rule_id):
        """Disable a rule"""
        with self.lock:
            if rule_id in self.auto_rules:
                self.auto_rules[rule_id].enabled = False
                self._save_all_rules()
                return True
            return False
    
    def delete_rule(self, rule_id):
        """Delete a rule"""
        with self.lock:
            if rule_id in self.auto_rules:
                rule = self.auto_rules[rule_id]
                # Remove from IP index
                if rule.src_ip in self.ip_rules:
                    self.ip_rules[rule.src_ip] = [r for r in self.ip_rules[rule.src_ip] if r.id != rule_id]
                del self.auto_rules[rule_id]
                self._save_all_rules()
                return True
            return False
    
    def check_packet_match(self, pkt_src, pkt_proto, pkt_dport):
        """Check if packet matches any auto-rule and return matching rule"""
        with self.lock:
            for rule in self.auto_rules.values():
                if rule.matches_packet(pkt_src, pkt_proto, pkt_dport):
                    rule.hit_count += 1
                    rule.last_hit = datetime.now()
                    return rule
            return None
    
    def _save_rule(self, rule):
        """Save a single rule to file (append mode)"""
        try:
            with open(self.auto_rules_file, 'a') as f:
                # Add comment with metadata
                f.write(f"# Auto-generated: {rule.anomaly_type} | Score: {rule.score:.2f} | {rule.created_at.isoformat()}\n")
                f.write(rule.to_rule_string() + '\n')
        except Exception as e:
            logger.error(f"Error saving rule to file: {e}")
    
    def _save_all_rules(self):
        """Save all rules to file (overwrite mode)"""
        try:
            with open(self.auto_rules_file, 'w') as f:
                f.write("# Auto-Generated NIDS Rules\n")
                f.write("# Format: alert [proto] [srcip] [srcport] --> [dstip] [dstport] [message]\n")
                f.write("# Do not edit manually - rules are auto-generated by the learning system\n\n")
                
                for rule in self.auto_rules.values():
                    f.write(f"# Auto-generated: {rule.anomaly_type} | Score: {rule.score:.2f}\n")
                    f.write(rule.to_rule_string() + '\n')
        except Exception as e:
            logger.error(f"Error saving rules to file: {e}")
    
    def _load_rules(self):
        """Load existing auto-generated rules from file"""
        if not os.path.exists(self.auto_rules_file):
            return
        
        try:
            with open(self.auto_rules_file, 'r') as f:
                current_rule = None
                current_meta = {}
                
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        if 'Auto-generated:' in line:
                            # Parse metadata
                            parts = line.replace('# Auto-generated:', '').strip().split('|')
                            if len(parts) >= 2:
                                current_meta['anomaly_type'] = parts[0].strip()
                                current_meta['score'] = float(parts[1].strip().replace('Score:', ''))
                        continue
                    
                    # Parse rule
                    if line.startswith('alert'):
                        parts = line.split()
                        if len(parts) >= 8:
                            rule = AutoRule(
                                src_ip=parts[2],
                                anomaly_type=current_meta.get('anomaly_type', 'unknown'),
                                rule_proto=parts[1],
                                dst_port=parts[6],
                                message=' '.join(parts[7:]),
                                score=current_meta.get('score', 0.5)
                            )
                            rule.enabled = True
                            rule.validated = True
                            
                            self.auto_rules[rule.id] = rule
                            self.ip_rules[rule.src_ip].append(rule)
                            
                            rule_hash = hashlib.md5(line.encode()).hexdigest()
                            self.generated_rule_hashes.add(rule_hash)
                            
                            current_meta = {}
        except Exception as e:
            logger.error(f"Error loading auto-rules: {e}")
    
    def get_statistics(self):
        """Get rule generator statistics"""
        with self.lock:
            return {
                'total_rules': len(self.auto_rules),
                'enabled_rules': len([r for r in self.auto_rules.values() if r.enabled]),
                'total_generated': self.stats['total_rules_generated'],
                'duplicates_prevented': self.stats['total_duplicates_prevented'],
                'rules_rejected': self.stats['rules_rejected'],
                'tracked_ips': len(self.ip_rules)
            }
    
    def get_rule_strings(self):
        """Get all enabled rules as rule strings (for loading into main NIDS)"""
        with self.lock:
            return [rule.to_rule_string() for rule in self.auto_rules.values() if rule.enabled]


# Factory function
def create_rule_generator(config=None):
    """Create and configure a rule generator"""
    config = config or {}
    
    generator = RuleGenerator(
        auto_rules_file=config.get('rules_file', 'auto_rules.txt')
    )
    
    return generator


if __name__ == '__main__':
    # Test the rule generator
    from anomaly_detector import Anomaly, AnomalyType
    
    generator = RuleGenerator()
    
    # Create test anomaly
    anomaly = Anomaly(
        src_ip='192.168.1.100',
        anomaly_type=AnomalyType.PORT_SCAN,
        score=0.85,
        features={'port_diversity': 25, 'connection_rate': 15}
    )
    
    # Generate rule
    rule = generator.generate_rule(anomaly)
    if rule:
        print(f"Generated rule: {rule.to_rule_string()}")
    
    print("\nAll rules:")
    for r in generator.get_all_rules():
        print(f"  {r['rule_string']}")
    
    print("\nStatistics:", generator.get_statistics())

