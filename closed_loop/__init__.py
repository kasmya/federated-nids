#!/usr/bin/env python3
"""
Closed-Loop NIDS Package
Layer 2 (Brain): Anomaly Detection
Layer 3 (Teacher): Rule Generation
"""

from .traffic_analyzer import TrafficFeatureExtractor, FeatureVector
from .baselines import AdaptiveBaseline, IPBaselineManager
from .anomaly_detector import SimpleAnomalyDetector, Anomaly, AnomalyType
from .rule_generator import RuleGenerator, AutoRule
from .learning_db import LearningDB, get_learning_db

__all__ = [
    # Traffic Analysis
    'TrafficFeatureExtractor',
    'FeatureVector',
    
    # Baselines
    'AdaptiveBaseline',
    'IPBaselineManager',
    
    # Anomaly Detection (Layer 2)
    'SimpleAnomalyDetector',
    'Anomaly',
    'AnomalyType',
    
    # Rule Generation (Layer 3)
    'RuleGenerator',
    'AutoRule',
    
    # Learning Database
    'LearningDB',
    'get_learning_db',
]

__version__ = '1.0.0'


class ClosedLoopNIDS:
    """
    Main class that orchestrates the closed-loop NIDS system.
    Combines Layer 2 (Anomaly Detection) and Layer 3 (Rule Generation).
    """
    
    def __init__(self, config=None):
        config = config or {}
        
        # Initialize components
        self.detector = SimpleAnomalyDetector(
            window_size_seconds=config.get('window_size', 10),
            detection_threshold=config.get('detection_threshold', 0.5)
        )
        
        self.rule_generator = RuleGenerator(
            auto_rules_file=config.get('auto_rules_file', 'auto_rules.txt')
        )
        
        self.learning_db = get_learning_db(
            db_path=config.get('db_path', 'learning.db')
        )
        
        # Connect components
        self.detector.set_anomaly_callback(self._on_anomaly_detected)
        
        # Configuration
        self.config = config
        self.auto_generate_rules = config.get('auto_generate_rules', True)
        
        # Learning session
        self.current_session = None
        
        # Track stats
        self.total_anomalies = 0
        self.total_rules_generated = 0
    
    def _on_anomaly_detected(self, anomaly):
        """Callback when anomaly is detected"""
        self.total_anomalies += 1
        
        # Record in database
        self.learning_db.record_anomaly(anomaly.to_dict())
        
        # Auto-generate rule if enabled
        if self.auto_generate_rules:
            rule = self.rule_generator.generate_rule(anomaly)
            if rule:
                self.total_rules_generated += 1
                anomaly.rule_generated = True
                anomaly.rule_id = rule.id
                
                # Record rule in database
                self.learning_db.record_rule(rule.to_dict())
                self.learning_db.update_anomaly_rule(anomaly.id, rule.id)
                
                # Notify (could be extended for real-time alerts)
                self._notify_rule_generated(rule)
    
    def _notify_rule_generated(self, rule):
        """Notify that a new rule was generated"""
        # This could be extended to send notifications
        import logging
        logging.info(f"Auto-generated rule: {rule.to_rule_string()}")
    
    def process_packet(self, packet_dict):
        """Process a packet through the closed-loop system"""
        return self.detector.process_packet(packet_dict)
    
    def get_status(self):
        """Get current system status"""
        return {
            'detector': self.detector.get_statistics(),
            'rule_generator': self.rule_generator.get_statistics(),
            'learning_db': self.learning_db.get_statistics(),
            'session': {
                'anomalies': self.total_anomalies,
                'rules_generated': self.total_rules_generated
            },
            'auto_generate_rules': self.auto_generate_rules
        }
    
    def get_anomalies(self, limit=20):
        """Get recent anomalies"""
        return self.detector.get_recent_anomalies(limit)
    
    def get_auto_rules(self):
        """Get all auto-generated rules"""
        return self.rule_generator.get_all_rules()
    
    def start_learning_session(self):
        """Start a new learning session"""
        self.current_session = self.learning_db.start_session()
        self.total_anomalies = 0
        self.total_rules_generated = 0
        return self.current_session
    
    def end_learning_session(self):
        """End the current learning session"""
        if self.current_session:
            self.learning_db.end_session(
                self.current_session,
                packets=self.detector.stats.get('total_packets_processed', 0),
                anomalies=self.total_anomalies,
                rules=self.total_rules_generated
            )
            self.current_session = None


def create_closed_loop_nids(config=None):
    """Factory function to create a ClosedLoopNIDS instance"""
    return ClosedLoopNIDS(config)

