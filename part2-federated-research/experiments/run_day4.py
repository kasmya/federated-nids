#!/usr/bin/env python3
"""
Day 4: Comprehensive Experiment Runner
=====================================
Run all 3 scenarios and collect paper-ready metrics.

Usage:
    python -m experiments.run_day4          # Run all scenarios
    python -m experiments.run_day4 --scenario iid
    python -m experiments.run_day4 --scenario non_iid
    python -m experiments.run_day4 --scenario zero_day
"""

import sys
import os
import json
import csv
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from collections import defaultdict
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from federation import FederatedClient, FederatedServer, RuleConsensusEngine, fedavg_aggregate
from core import ClosedLoopNIDS, Anomaly, AttackType


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class RoundMetrics:
    """Metrics for a single round"""
    round_num: int
    client_id: str
    packets_processed: int
    anomalies_detected: int
    rules_generated: int
    detection_accuracy: float
    true_positives: int
    false_positives: int
    global_rules_received: int
    timestamp: str


@dataclass
class ScenarioResults:
    """Results for a complete scenario"""
    scenario_name: str
    num_rounds: int
    total_rounds_with_global_rule: int
    rounds_until_first_global_rule: int
    total_global_rules: int
    round_metrics: List[RoundMetrics] = field(default_factory=list)
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'scenario_name': self.scenario_name,
            'num_rounds': self.num_rounds,
            'total_rounds_with_global_rule': self.total_rounds_with_global_rule,
            'rounds_until_first_global_rule': self.rounds_until_first_global_rule,
            'total_global_rules': self.total_global_rules,
            'timestamp': self.timestamp,
            'round_metrics': [
                {
                    'round_num': rm.round_num,
                    'client_id': rm.client_id,
                    'packets_processed': rm.packets_processed,
                    'anomalies_detected': rm.anomalies_detected,
                    'rules_generated': rm.rules_generated,
                    'detection_accuracy': rm.detection_accuracy,
                    'true_positives': rm.true_positives,
                    'false_positives': rm.false_positives,
                    'global_rules_received': rm.global_rules_received,
                    'timestamp': rm.timestamp
                }
                for rm in self.round_metrics
            ]
        }


# =============================================================================
# ENHANCED CLIENT WITH BETTER METRICS
# =============================================================================

class EnhancedFederatedClient(FederatedClient):
    """Enhanced client with detailed metrics tracking"""
    
    def __init__(self, client_id: str, traffic_pattern: str = "normal", 
                 packets_per_round: int = 100):
        super().__init__(client_id, traffic_pattern)
        # Increase default packets to trigger detection thresholds
        # Need at least 60 unique ports for port_scan detection
        self.packets_per_round = max(packets_per_round, 200)
        self.global_rules_received = 0
        self.detection_history = []
        self.rule_history = []
        
    def fit(self, parameters, config: Dict):
        """Enhanced fit with detailed metrics"""
        round_num = config.get('round_number', self.round_count)
        
        # Apply global parameters
        self.set_parameters(parameters)
        
        # Get custom packet generator if provided
        packet_generator = config.get('packet_generator')
        
        if packet_generator:
            packets = packet_generator(self.cid, round_num, self.packets_per_round)
        else:
            packets = self._generate_traffic(self.packets_per_round)
        
        # Process packets
        anomalies = 0
        rules_generated = 0
        true_positives = 0
        false_positives = 0
        
        for pkt in packets:
            anomaly = self.nids.process_packet(pkt)
            
            # Track detection
            is_attack = pkt.get('is_attack', False)
            
            if anomaly:
                anomalies += 1
                rules_generated += 1
                if is_attack:
                    true_positives += 1
                else:
                    false_positives += 1
        
        # Calculate accuracy
        total_attacks = sum(1 for p in packets if p.get('is_attack', False))
        detection_accuracy = true_positives / max(total_attacks, 1)
        
        # Get updated parameters
        new_params = self.get_parameters()
        
        # Track metrics
        metrics = {
            'loss': 1.0 - detection_accuracy,
            'anomalies_detected': anomalies,
            'rules_generated': rules_generated,
            'packets_processed': len(packets),
            'detection_accuracy': detection_accuracy,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'global_rules_received': self.global_rules_received,
        }
        
        self.detection_history.append({
            'round': round_num,
            'accuracy': detection_accuracy,
            'tp': true_positives,
            'fp': false_positives
        })
        
        self.rule_history.append(rules_generated)
        
        print(f"[{self.cid}] Round {round_num}: {anomalies} anomalies, "
              f"{rules_generated} rules, {detection_accuracy:.2%} accuracy")
        
        return new_params, len(packets), metrics
    
    def receive_global_rules(self, global_rules: List[Dict]):
        """Receive global rules from server"""
        self.global_rules_received = len(global_rules)
        if global_rules:
            print(f"[{self.cid}] Received {len(global_rules)} global rules")


# =============================================================================
# TRAFFIC PATTERNS FOR EACH SCENARIO
# =============================================================================

def generate_iid_traffic(client_id: str, round_num: int, num_packets: int) -> List[Dict]:
    """
    Scenario 1: IID Data (Baseline)
    All clients see similar traffic distribution: 30% attacks, 70% normal
    
    Added realistic noise:
    - Some attacks are subtle (below threshold) = false negatives
    - Some normal traffic looks suspicious = false positives
    """
    import random
    random.seed(round_num * 1000 + hash(client_id) % 100)  # Reproducible but varied
    
    packets = []
    
    # Ensure minimum packets for detection
    num_packets = max(num_packets, 400)
    
    # Calculate attack count
    num_packets = max(num_packets, 400)
    
    attack_count = int(num_packets * 0.3)
    normal_count = num_packets - attack_count
    
    # Generate port scan attacks with noise
    # Some are "subtle" - won't trigger detection (false negatives)
    port_scan_count = attack_count // 2
    for i in range(port_scan_count):
        # 20% of attacks are subtle (fewer ports, below threshold)
        is_subtle = random.random() < 0.2
        if is_subtle:
            # Fewer unique ports - below detection threshold
            dport = (i % 10) + 1  # Only 10 unique ports
        else:
            dport = (i % 70) + 1  # 70 unique ports - detected
            
        packets.append({
            'src': '192.168.1.100', 'dst': '10.0.0.1',
            'proto': 'tcp', 'dport': dport,
            'flags': 'S', 'length': 64,
            'is_attack': True, 'attack_type': 'port_scan'
        })
    
    # Generate SYN flood attacks with noise
    syn_flood_count = attack_count - port_scan_count
    for i in range(syn_flood_count):
        # 15% are subtle
        is_subtle = random.random() < 0.15
        if is_subtle:
            flags = 'PA'  # Not SYN, won't trigger
        else:
            flags = 'S'
            
        packets.append({
            'src': '192.168.1.200', 'dst': '10.0.0.2',
            'proto': 'tcp', 'dport': 80,
            'flags': flags, 'length': 64,
            'is_attack': True, 'attack_type': 'syn_flood'
        })
    
    # Generate normal traffic - some looks suspicious (false positives)
    for i in range(normal_count):
        # 10% of normal traffic looks suspicious
        looks_suspicious = random.random() < 0.1
        if looks_suspicious:
            # Multiple ports from same IP - might trigger false positive
            packets.append({
                'src': '192.168.1.50', 'dst': '10.0.0.10',
                'proto': 'tcp', 'dport': [80, 443, 8080, 22][i % 4],
                'flags': 'S', 'length': 64,  # SYN looks like scan
                'is_attack': False
            })
        else:
            packets.append({
                'src': f'192.168.1.{10 + (i % 5)}', 'dst': '10.0.0.10',
                'proto': 'tcp', 'dport': [80, 443, 22][i % 3],
                'flags': 'PA', 'length': 500 + (i % 100),
                'is_attack': False
            })
    
    # Shuffle to simulate real network traffic
    random.shuffle(packets)
    
    return packets


def generate_non_iid_traffic(client_id: str, round_num: int, num_packets: int) -> List[Dict]:
    """
    Scenario 2: Non-IID Data (Realistic)
    - Client A: 60% port scans, 20% normal, 20% other
    - Client B: 60% SYN floods, 20% normal, 20% other
    - Client C: 90% normal, 10% mixed attacks
    
    Added noise for realism:
    - Some attacks are subtle (false negatives)
    - Some normal looks suspicious (false positives)
    """
    import random
    random.seed(round_num * 1000 + hash(client_id) % 100)
    
    packets = []
    
    # Ensure minimum packets
    num_packets = max(num_packets, 200)
    num_packets = max(num_packets, 200)
    
    if client_id == 'client_A':
        # 60% port_scan, 20% normal, 20% other
        port_scan = int(num_packets * 0.6)
        normal = int(num_packets * 0.2)
        other = num_packets - port_scan - normal
        
        # Port scan with noise - 25% subtle attacks
        for i in range(port_scan):
            is_subtle = random.random() < 0.25
            if is_subtle:
                dport = (i % 10) + 1
            else:
                dport = (i % 70) + 1
            packets.append({
                'src': '192.168.1.100', 'dst': '10.0.0.1',
                'proto': 'tcp', 'dport': dport,
                'flags': 'S', 'length': 64,
                'is_attack': True, 'attack_type': 'port_scan'
            })
        
        # Normal with 10% false positives
        for i in range(normal):
            if random.random() < 0.1:
                packets.append({
                    'src': '192.168.1.50', 'dst': '10.0.0.10',
                    'proto': 'tcp', 'dport': [80, 443][i % 2],
                    'flags': 'S', 'length': 64,
                    'is_attack': False
                })
            else:
                packets.append({
                    'src': '192.168.1.10', 'dst': '10.0.0.10',
                    'proto': 'tcp', 'dport': 80, 'flags': 'PA',
                    'length': 500, 'is_attack': False
                })
        
        # Other attacks with noise
        for i in range(other):
            if random.random() < 0.2:
                packets.append({'src': '192.168.1.200', 'dst': '10.0.0.2',
                    'proto': 'tcp', 'dport': 80, 'flags': 'PA',
                    'length': 500, 'is_attack': True, 'attack_type': 'syn_flood'})
            else:
                packets.append({
                    'src': '192.168.1.200', 'dst': '10.0.0.2',
                    'proto': 'tcp', 'dport': 80, 'flags': 'S',
                    'length': 64, 'is_attack': True, 'attack_type': 'syn_flood'
                })
            
    elif client_id == 'client_B':
        # 60% syn_flood, 20% normal, 20% other
        syn_flood = int(num_packets * 0.6)
        normal = int(num_packets * 0.2)
        other = num_packets - syn_flood - normal
        
        # SYN flood with noise - 20% subtle
        for i in range(syn_flood):
            if random.random() < 0.2:
                flags = 'PA'
            else:
                flags = 'S'
            packets.append({
                'src': '192.168.1.200', 'dst': '10.0.0.2',
                'proto': 'tcp', 'dport': 80, 'flags': flags,
                'length': 64, 'is_attack': True, 'attack_type': 'syn_flood'
            })
        
        # Normal with false positives
        for i in range(normal):
            if random.random() < 0.1:
                packets.append({
                    'src': '192.168.1.51', 'dst': '10.0.0.11',
                    'proto': 'tcp', 'dport': 80, 'flags': 'S',
                    'length': 64, 'is_attack': False
                })
            else:
                packets.append({
                    'src': '192.168.1.11', 'dst': '10.0.0.11',
                    'proto': 'tcp', 'dport': 443, 'flags': 'PA',
                    'length': 600, 'is_attack': False
                })
        
        # Other - port scans with noise
        for i in range(other):
            if random.random() < 0.25:
                dport = (i % 10) + 1
            else:
                dport = (i % 60) + 1
            packets.append({
                'src': '192.168.1.100', 'dst': '10.0.0.1',
                'proto': 'tcp', 'dport': dport,
                'flags': 'S', 'length': 64, 'is_attack': True, 'attack_type': 'port_scan'
            })
            
    else:  # client_C
        # 90% normal, 10% mixed
        normal = int(num_packets * 0.9)
        attacks = num_packets - normal
        
        for i in range(normal):
            if random.random() < 0.05:  # 5% false positive
                packets.append({
                    'src': '192.168.1.52', 'dst': '10.0.0.12',
                    'proto': 'tcp', 'dport': 80, 'flags': 'S',
                    'length': 64, 'is_attack': False
                })
            else:
                packets.append({
                    'src': f'192.168.1.{12 + (i % 3)}', 'dst': '10.0.0.12',
                    'proto': 'tcp', 'dport': [80, 443, 22][i % 3],
                    'flags': 'PA', 'length': 500 + (i % 100),
                    'is_attack': False
                })
        
        for i in range(attacks):
            if random.random() < 0.3:  # 30% subtle
                packets.append({
                    'src': '192.168.1.100', 'dst': '10.0.0.1',
                    'proto': 'tcp', 'dport': (i % 5) + 1,
                    'flags': 'PA', 'length': 500,
                    'is_attack': True, 'attack_type': 'port_scan'
                })
            else:
                if i % 2 == 0:
                    packets.append({
                        'src': '192.168.1.100', 'dst': '10.0.0.1',
                        'proto': 'tcp', 'dport': (i % 30) + 1,
                        'flags': 'S', 'length': 64,
                        'is_attack': True, 'attack_type': 'port_scan'
                    })
                else:
                    packets.append({
                        'src': '192.168.1.200', 'dst': '10.0.0.2',
                        'proto': 'tcp', 'dport': 80, 'flags': 'S',
                        'length': 64, 'is_attack': True, 'attack_type': 'syn_flood'
                    })
    
    random.shuffle(packets)
    return packets


def generate_zero_day_traffic(client_id: str, round_num: int, 
                               num_packets: int, zero_day_round: int = 6) -> List[Dict]:
    """
    Scenario 3: Zero-Day Simulation
    - Rounds 1-5: Non-IID data (baseline)
    - Round 6: Inject novel attack (zero-day) into Client A only
    - Track how quickly the zero-day is detected and propagates
    """
    import random
    random.seed(round_num * 1000 + hash(client_id) % 100)
    
    packets = []
    
    # Ensure minimum packets
    num_packets = max(num_packets, 200)
    
    # Check if this is the zero-day round
    is_zero_day = (round_num == zero_day_round)
    
    if is_zero_day and client_id == 'client_A':
        # Zero-day attack: brand new attack pattern never seen before
        print(f"[ZERO-DAY] Round {round_num}: Injecting zero-day attack!")
        
        zero_day_attacks = int(num_packets * 0.4)
        normal = num_packets - zero_day_attacks
        
        # Zero-day is subtle - only 30% are detectable
        # This simulates a novel attack that partially evades detection
        for i in range(zero_day_attacks):
            is_detectable = random.random() < 0.3
            if is_detectable:
                # Clear zero-day pattern
                packets.append({
                    'src': '10.255.255.999',  # NEW IP range
                    'dst': '10.0.0.99',
                    'proto': 'tcp', 
                    'dport': 9999,
                    'flags': 'S', 
                    'length': 128,
                    'is_attack': True, 
                    'attack_type': 'zero_day',
                    'is_zero_day': True
                })
            else:
                # Subtle variant - might not be detected
                packets.append({
                    'src': '10.255.255.999',
                    'dst': '10.0.0.99',
                    'proto': 'tcp', 
                    'dport': 80,  # Use common port
                    'flags': 'PA',  # Not SYN
                    'length': 500,  # Normal size
                    'is_attack': True, 
                    'attack_type': 'zero_day',
                    'is_zero_day': True
                })
        
        # Normal with some false positives
        for i in range(normal):
            if random.random() < 0.1:
                packets.append({
                    'src': '192.168.1.50', 'dst': '10.0.0.10',
                    'proto': 'tcp', 'dport': 80, 'flags': 'S',
                    'length': 64, 'is_attack': False
                })
            else:
                packets.append({
                    'src': '192.168.1.10', 'dst': '10.0.0.10',
                    'proto': 'tcp', 'dport': 80, 'flags': 'PA',
                    'length': 500, 'is_attack': False
                })
    else:
        # Pre-zero-day: use non-IID pattern with noise
        packets = generate_non_iid_traffic(client_id, round_num, num_packets)
    
    return packets


# =============================================================================
# EXPERIMENT RUNNERS
# =============================================================================

class ExperimentRunner:
    """Comprehensive experiment runner with metrics collection"""
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Setup detailed logging for methodology section"""
        logger = logging.getLogger('experiment')
        logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        logger.handlers = []
        
        # File handler
        log_file = os.path.join(self.output_dir, f"experiment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Format
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger
    
    def run_scenario(self, scenario: str, num_rounds: int = 10,
                    packets_per_round: int = 100) -> ScenarioResults:
        """Run a single scenario"""
        
        self.logger.info(f"="*60)
        self.logger.info(f"STARTING SCENARIO: {scenario.upper()}")
        self.logger.info(f"Rounds: {num_rounds}, Packets/round: {packets_per_round}")
        self.logger.info(f"="*60)
        
        # Select traffic generator
        if scenario == 'iid':
            traffic_gen = generate_iid_traffic
        elif scenario == 'non_iid':
            traffic_gen = generate_non_iid_traffic
        elif scenario == 'zero_day':
            traffic_gen = generate_zero_day_traffic
        else:
            raise ValueError(f"Unknown scenario: {scenario}")
        
        # Create clients
        clients = [
            EnhancedFederatedClient("client_A", "port_scan", packets_per_round),
            EnhancedFederatedClient("client_B", "syn_flood", packets_per_round),
            EnhancedFederatedClient("client_C", "mixed", packets_per_round),
        ]
        
        # Create server with consensus
        server = FederatedServer(num_rounds=num_rounds)
        
        # Track metrics
        all_metrics = []
        first_global_rule_round = -1
        rounds_with_global = 0
        
        # Run federated rounds
        for round_num in range(1, num_rounds + 1):
            self.logger.info(f"\n--- ROUND {round_num}/{num_rounds} ---")
            
            # Collect client results
            client_params = []
            client_results = []
            
            for client in clients:
                # Fit with custom traffic generator
                config = {
                    'round_number': round_num,
                    'packet_generator': traffic_gen
                }
                
                new_params, n_samples, metrics = client.fit(
                    client.get_parameters() if round_num == 1 else server.global_params,
                    config
                )
                
                client_params.append(new_params)
                client_results.append({
                    'cid': client.cid,
                    'samples': n_samples,
                    'metrics': metrics
                })
                
                # Record round metrics
                rm = RoundMetrics(
                    round_num=round_num,
                    client_id=client.cid,
                    packets_processed=metrics.get('packets_processed', 0),
                    anomalies_detected=metrics.get('anomalies_detected', 0),
                    rules_generated=metrics.get('rules_generated', 0),
                    detection_accuracy=metrics.get('detection_accuracy', 0),
                    true_positives=metrics.get('true_positives', 0),
                    false_positives=metrics.get('false_positives', 0),
                    global_rules_received=metrics.get('global_rules_received', 0),
                    timestamp=datetime.now().isoformat()
                )
                all_metrics.append(rm)
            
            # Submit rules to consensus
            global_rules = []
            for client in clients:
                for rule in client.get_local_rules():
                    result = server.consensus.submit_rule(rule, client.cid)
                    if result.get('global'):
                        self.logger.info(f"★ CONSENSUS: Rule promoted to global!")
                        if first_global_rule_round == -1:
                            first_global_rule_round = round_num
                        rounds_with_global += 1
                        global_rules.append(rule)
            
            # Distribute global rules to clients
            for client in clients:
                client.receive_global_rules(global_rules)
            
            # Aggregate parameters
            server.global_params = fedavg_aggregate(client_params)
            
            self.logger.info(f"Round {round_num} complete: {len(global_rules)} global rules")
        
        # Compile results
        results = ScenarioResults(
            scenario_name=scenario,
            num_rounds=num_rounds,
            total_rounds_with_global_rule=rounds_with_global,
            rounds_until_first_global_rule=first_global_rule_round,
            total_global_rules=len(server.consensus.get_global_rules()),
            round_metrics=all_metrics,
            timestamp=datetime.now().isoformat()
        )
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"SCENARIO COMPLETE: {scenario.upper()}")
        self.logger.info(f"Total global rules: {results.total_global_rules}")
        self.logger.info(f"First global rule at round: {results.rounds_until_first_global_rule}")
        self.logger.info(f"{'='*60}")
        
        return results
    
    def export_to_csv(self, results: ScenarioResults, filename: str = None):
        """Export results to CSV"""
        if filename is None:
            filename = f"scenario_{results.scenario_name}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'round', 'client', 'packets', 'anomalies', 'rules',
                'accuracy', 'true_positives', 'false_positives', 
                'global_rules', 'timestamp'
            ])
            
            for rm in results.round_metrics:
                writer.writerow([
                    rm.round_num, rm.client_id, rm.packets_processed,
                    rm.anomalies_detected, rm.rules_generated,
                    f"{rm.detection_accuracy:.4f}", rm.true_positives,
                    rm.false_positives, rm.global_rules_received,
                    rm.timestamp
                ])
        
        self.logger.info(f"CSV exported: {filepath}")
        return filepath
    
    def export_summary_json(self, all_results: Dict[str, ScenarioResults]):
        """Export summary statistics to JSON"""
        summary = {}
        
        for scenario, results in all_results.items():
            # Calculate aggregate stats
            total_rules = sum(m.rules_generated for m in results.round_metrics)
            avg_accuracy = sum(m.detection_accuracy for m in results.round_metrics) / max(len(results.round_metrics), 1)
            
            # Per-client stats
            client_stats = {}
            for rm in results.round_metrics:
                if rm.client_id not in client_stats:
                    client_stats[rm.client_id] = {
                        'total_rules': 0,
                        'total_detections': 0,
                        'avg_accuracy': []
                    }
                client_stats[rm.client_id]['total_rules'] += rm.rules_generated
                client_stats[rm.client_id]['total_detections'] += rm.anomalies_detected
                client_stats[rm.client_id]['avg_accuracy'].append(rm.detection_accuracy)
            
            # Average per client
            for cid in client_stats:
                accs = client_stats[cid]['avg_accuracy']
                client_stats[cid]['avg_accuracy'] = sum(accs) / max(len(accs), 1)
            
            summary[scenario] = {
                'num_rounds': results.num_rounds,
                'total_global_rules': results.total_global_rules,
                'rounds_until_first_global': results.rounds_until_first_global_rule,
                'total_rules_generated': total_rules,
                'average_detection_accuracy': avg_accuracy,
                'rounds_with_global_rule': results.total_rounds_with_global_rule,
                'client_stats': client_stats,
                'timestamp': results.timestamp
            }
        
        filepath = os.path.join(self.output_dir, "summary_stats.json")
        
        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Summary exported: {filepath}")
        return summary


def run_all_scenarios():
    """Run all 3 scenarios sequentially"""
    
    print("\n" + "="*60)
    print("DAY 4: RUNNING ALL EXPERIMENTS")
    print("="*60)
    
    runner = ExperimentRunner()
    all_results = {}
    
    # Scenario 1: IID (10 rounds)
    print("\n[1/3] Running IID scenario...")
    results_iid = runner.run_scenario('iid', num_rounds=10)
    all_results['iid'] = results_iid
    runner.export_to_csv(results_iid)
    
    # Scenario 2: Non-IID (15 rounds)
    print("\n[2/3] Running Non-IID scenario...")
    results_non_iid = runner.run_scenario('non_iid', num_rounds=15)
    all_results['non_iid'] = results_non_iid
    runner.export_to_csv(results_non_iid)
    
    # Scenario 3: Zero-Day (15 rounds with zero-day at round 6)
    print("\n[3/3] Running Zero-Day scenario...")
    results_zero_day = runner.run_scenario('zero_day', num_rounds=15)
    all_results['zero_day'] = results_zero_day
    runner.export_to_csv(results_zero_day)
    
    # Export summary
    summary = runner.export_summary_json(all_results)
    
    # Print final summary
    print("\n" + "="*60)
    print("ALL SCENARIOS COMPLETE")
    print("="*60)
    
    for scenario, stats in summary.items():
        print(f"\n{scenario.upper()}:")
        print(f"  Global rules: {stats['total_global_rules']}")
        print(f"  First global at round: {stats['rounds_until_first_global']}")
        print(f"  Avg accuracy: {stats['average_detection_accuracy']:.2%}")
    
    print(f"\n✓ Results saved to: {runner.output_dir}/")
    
    return all_results


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='Day 4 Experiment Runner')
    parser.add_argument('--scenario', choices=['iid', 'non_iid', 'zero_day'],
                       help='Specific scenario to run')
    parser.add_argument('--rounds', type=int, default=10,
                       help='Number of rounds')
    parser.add_argument('--packets', type=int, default=100,
                       help='Packets per round')
    
    args = parser.parse_args()
    
    runner = ExperimentRunner()
    
    if args.scenario:
        # Run single scenario
        results = runner.run_scenario(args.scenario, args.rounds, args.packets)
        runner.export_to_csv(results)
        
        print(f"\n✓ Scenario complete!")
        print(f"  Global rules: {results.total_global_rules}")
        print(f"  First global at round: {results.rounds_until_first_global_rule}")
    else:
        # Run all scenarios
        run_all_scenarios()


if __name__ == "__main__":
    main()

