#!/usr/bin/env python3
"""
Enhanced Experiment Runner with ML-based Detection
=====================================================
Uses RandomForest for real ML-based detection + Federation comparison
"""

import sys
import os
import json
import csv
import random
import numpy as np
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass, field
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from federation import FederatedClient, FederatedServer, RuleConsensusEngine, fedavg_aggregate


# =============================================================================
# ML-BASED DETECTOR (RandomForest)
# =============================================================================

class MLDetector:
    """
    ML-based detector using RandomForest
    This replaces the simple threshold-based detector for more realistic results
    """
    
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.feature_names = ['src_port', 'dst_port', 'packet_size', 
                              'proto_tcp', 'proto_udp', 'proto_icmp',
                              'flag_S', 'flag_PA', 'flag_RA']
        self._init_model()
    
    def _init_model(self):
        """Initialize a simple decision tree as fallback"""
        try:
            from sklearn.ensemble import RandomForestClassifier
            self.model = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
            self.sklearn_available = True
        except ImportError:
            self.sklearn_available = False
            # Use simple heuristic-based detection as fallback
            self.baselines = {}
    
    def _extract_features(self, packet: Dict) -> List[float]:
        """Extract features from packet"""
        src = packet.get('src', '0.0.0.0')
        dst = packet.get('dst', '0.0.0.0')
        
        # Parse IPs to numeric
        try:
            src_octets = [int(x) for x in src.split('.')]
            dst_octets = [int(x) for x in dst.split('.')]
            src_port = src_octets[3] if len(src_octets) == 4 else 0
            dst_port = packet.get('dport', 0)
        except:
            src_port = hash(src) % 65535
            dst_port = packet.get('dport', 0)
        
        packet_size = packet.get('length', 64)
        proto = packet.get('proto', 'tcp').lower()
        flags = packet.get('flags', '').upper()
        
        return [
            float(src_port),
            float(dst_port),
            float(packet_size),
            1.0 if proto == 'tcp' else 0.0,
            1.0 if proto == 'udp' else 0.0,
            1.0 if proto == 'icmp' else 0.0,
            1.0 if 'S' in flags else 0.0,
            1.0 if 'PA' in flags else 0.0,
            1.0 if 'RA' in flags else 0.0,
        ]
    
    def _heuristic_detect(self, packet: Dict) -> bool:
        """Fallback heuristic detection when sklearn unavailable"""
        src = packet.get('src', '')
        dst_port = packet.get('dport', 0)
        flags = packet.get('flags', '').upper()
        
        # Track source IP behavior
        if src not in self.baselines:
            self.baselines[src] = {'ports': set(), 'packets': 0, 'syn_count': 0}
        
        bl = self.baselines[src]
        bl['packets'] += 1
        bl['ports'].add(dst_port)
        if 'S' in flags:
            bl['syn_count'] += 1
        
        # Port scan: many different ports from same IP
        if len(bl['ports']) > 15:
            return True
        
        # SYN flood: many SYN packets
        if bl['syn_count'] > 20 and bl['packets'] > 30:
            return True
        
        return False
    
    def train(self, packets: List[Dict], labels: List[int]):
        """Train on packets"""
        if self.sklearn_available:
            X = np.array([self._extract_features(p) for p in packets])
            y = np.array(labels)
            self.model.fit(X, y)
            self.is_trained = True
        else:
            # Just track baselines for heuristic
            for pkt, label in zip(packets, labels):
                if label == 1:
                    self._heuristic_detect(pkt)
            self.is_trained = True
    
    def predict(self, packet: Dict) -> bool:
        """Predict if packet is attack"""
        if self.sklearn_available and self.is_trained:
            X = np.array([self._extract_features(packet)])
            pred = self.model.predict(X)
            return pred[0] == 1
        else:
            return self._heuristic_detect(packet)
    
    def predict_proba(self, packet: Dict) -> float:
        """Get attack probability"""
        if self.sklearn_available and self.is_trained:
            X = np.array([self._extract_features(packet)])
            prob = self.model.predict_proba(X)
            return prob[0][1] if len(prob[0]) > 1 else 0.5
        else:
            return 0.5 if self._heuristic_detect(packet) else 0.1


# =============================================================================
# DATA STRUCTURES  
# =============================================================================

@dataclass
class RoundMetrics:
    round_num: int
    client_id: str
    packets_processed: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    rules_generated: int
    global_rules_received: int
    timestamp: str


@dataclass
class ScenarioResults:
    scenario_name: str
    num_rounds: int
    num_clients: int
    use_federation: bool
    round_metrics: List[RoundMetrics] = field(default_factory=list)
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'scenario_name': self.scenario_name,
            'num_rounds': self.num_rounds,
            'num_clients': self.num_clients,
            'use_federation': self.use_federation,
            'timestamp': self.timestamp,
            'final_metrics': self.get_final_metrics()
        }
    
    def get_final_metrics(self) -> Dict:
        if not self.round_metrics:
            return {}
        
        # Average across all rounds and clients
        metrics = self.round_metrics
        return {
            'avg_accuracy': sum(m.accuracy for m in metrics) / len(metrics),
            'avg_precision': sum(m.precision for m in metrics) / len(metrics),
            'avg_recall': sum(m.recall for m in metrics) / len(metrics),
            'avg_f1': sum(m.f1_score for m in metrics) / len(metrics),
            'total_rules': sum(m.rules_generated for m in metrics),
        }


# =============================================================================
# TRAFFIC GENERATORS WITH REALISTIC NOISE
# =============================================================================

def generate_realistic_traffic(client_id: str, round_num: int, 
                               num_packets: int, scenario: str = 'iid',
                               for_training: bool = False) -> List[Dict]:
    """
    Generate realistic network traffic with train/test drift
    
    If for_training=True: Uses known patterns that ML can learn
    If for_training=False: Uses slightly different patterns (test drift)
    This simulates real-world attack evolution
    """
    random.seed(round_num * 1000 + hash(client_id) % 100 + (1 if for_training else 0))
    
    packets = []
    num_packets = max(num_packets, 300)
    
    if scenario == 'iid':
        attack_rate = 0.25
    elif scenario == 'non_iid':
        if client_id == 'client_A':
            attack_rate = 0.50
        elif client_id == 'client_B':
            attack_rate = 0.40
        else:
            attack_rate = 0.10
    else:
        attack_rate = 0.40
    
    attack_count = int(num_packets * attack_rate)
    normal_count = num_packets - attack_count
    
    # Training uses cleaner patterns; test has drift (different IPs, ports)
    offset = 100 if not for_training else 0
    
    # Generate attacks - test data has evolved patterns
    for i in range(attack_count):
        is_subtle = random.random() < 0.20
        
        # Test data uses DIFFERENT IP ranges (drift)
        if not for_training:
            # Shift IPs for test - simulates attack evolution
            base_ip = 10 if is_subtle else 172  # Different from training
        else:
            base_ip = 192
        
        is_portscan = random.random() < 0.5
        
        if is_portscan:
            # Test uses different port ranges
            port_range = 30 if not for_training else 50
            pkt = {
                'src': f'192.168.{base_ip}.100',
                'dst': '10.0.0.1',
                'proto': 'tcp',
                'dport': (i % port_range) + 1 if not is_subtle else (i % 5) + 1,
                'flags': 'S' if not is_subtle else 'PA',
                'length': 64 if not is_subtle else 500,
                'is_attack': True,
                'attack_type': 'port_scan'
            }
        else:
            pkt = {
                'src': f'192.168.{base_ip}.{200 + (i % 5)}',
                'dst': '10.0.0.2',
                'proto': 'tcp',
                'dport': 8080 if not for_training else 80,
                'flags': 'S' if not is_subtle else 'PA',
                'length': 64,
                'is_attack': True,
                'attack_type': 'syn_flood'
            }
        packets.append(pkt)
    
    # Generate normal traffic - some suspicious (false positives)
    for i in range(normal_count):
        is_fp = random.random() < 0.08
        
        if is_fp:
            # Test has different benign-but-suspicious patterns
            benign_ip = 50 if not for_training else 50
            pkt = {
                'src': f'192.168.{benign_ip}.{i % 10}',
                'dst': '10.0.0.10',
                'proto': 'tcp',
                'dport': [80, 443, 8080][i % 3],
                'flags': 'S',
                'length': 64,
                'is_attack': False
            }
        else:
            pkt = {
                'src': f'192.168.1.{10 + (i % 20)}',
                'dst': '10.0.0.10',
                'proto': ['tcp', 'tcp', 'udp'][i % 3],
                'dport': [80, 443, 22, 53][i % 4],
                'flags': 'PA',
                'length': 200 + (i % 500),
                'is_attack': False
            }
        packets.append(pkt)
    
    random.shuffle(packets)
    return packets


# =============================================================================
# FEDERATED CLIENT WITH ML DETECTOR
# =============================================================================

class MLFederatedClient:
    """Federated client with ML-based detection"""
    
    def __init__(self, client_id: str, packets_per_round: int = 300):
        self.cid = client_id
        self.packets_per_round = packets_per_round
        self.detector = MLDetector()
        self.global_rules_received = 0
        self.round_count = 0
        self.training_packets = []  # Historical data for training
        self.is_initialized = False
        
    def get_parameters(self):
        """Get model parameters (placeholder for actual FL)"""
        return np.array([0.5], dtype=np.float32)
    
    def set_parameters(self, params):
        """Apply federated parameters"""
        pass
    
    def fit(self, parameters, config: Dict):
        """Process packets and update model"""
        self.round_count += 1
        round_num = config.get('round_number', self.round_count)
        scenario = config.get('scenario', 'iid')
        
        self.set_parameters(parameters)
        
        # Generate TRAINING data (for building model)
        train_packets = generate_realistic_traffic(self.cid, round_num, 
                                                  self.packets_per_round // 2, 
                                                  scenario, for_training=True)
        
        # Add to training history
        self.training_packets.extend(train_packets)
        
        # Train after accumulating enough data
        if not self.is_initialized and len(self.training_packets) >= 100:
            train_labels = [1 if p.get('is_attack', False) else 0 for p in self.training_packets]
            self.detector.train(self.training_packets, train_labels)
            self.is_initialized = True
            print(f"[{self.cid}] Model trained on {len(self.training_packets)} samples")
        
        # Generate FRESH test data (for evaluation) - has drift from training
        test_packets = generate_realistic_traffic(self.cid, round_num + 100, 
                                                self.packets_per_round // 2,
                                                scenario, for_training=False)
        
        # Evaluate on FRESH data
        tp = fp = tn = fn = 0
        rules = 0
        
        for pkt in test_packets:
            is_attack = pkt.get('is_attack', False)
            
            # Only predict if model is trained
            if self.is_initialized:
                detected = self.detector.predict(pkt)
            else:
                # Random guess before training (baseline)
                detected = random.random() < 0.25
            
            if detected and is_attack:
                tp += 1
                rules += 1
            elif detected and not is_attack:
                fp += 1
            elif not detected and is_attack:
                fn += 1
            else:
                tn += 1
        
        # Calculate metrics
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / max(total, 1)
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.001)
        
        metrics = RoundMetrics(
            round_num=round_num,
            client_id=self.cid,
            packets_processed=len(test_packets),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            rules_generated=rules,
            global_rules_received=self.global_rules_received,
            timestamp=datetime.now().isoformat()
        )
        
        print(f"[{self.cid}] R{round_num}: Acc={accuracy:.1%}, "
              f"P={precision:.1%}, R={recall:.1%}, F1={f1:.1%}")
        
        return self.get_parameters(), len(test_packets), metrics
    
    def receive_global_rules(self, rules: List):
        """Receive global rules from federation"""
        self.global_rules_received = len(rules)
    
    def get_local_rules(self) -> List[Dict]:
        """Get local detection rules"""
        return []


# =============================================================================
# EXPERIMENT RUNNER
# =============================================================================

class EnhancedExperimentRunner:
    """Enhanced experiment runner with ML + federation comparison"""
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def run_scenario(self, scenario: str, num_rounds: int = 10,
                    use_federation: bool = True) -> ScenarioResults:
        """Run a scenario with or without federation"""
        
        print(f"\n{'='*60}")
        mode = "FEDERATED" if use_federation else "NO FEDERATION"
        print(f"SCENARIO: {scenario.upper()} | MODE: {mode}")
        print(f"{'='*60}")
        
        # Create clients
        clients = [
            MLFederatedClient("client_A", 300),
            MLFederatedClient("client_B", 300),
            MLFederatedClient("client_C", 300),
        ]
        
        # Create server
        server = FederatedServer(num_rounds=num_rounds) if use_federation else None
        
        all_metrics = []
        
        # Run rounds
        for round_num in range(1, num_rounds + 1):
            client_params = []
            round_metrics = []
            
            for client in clients:
                config = {
                    'round_number': round_num,
                    'scenario': scenario
                }
                
                params, n_samples, metrics = client.fit(
                    client.get_parameters() if round_num == 1 
                    else (server.global_params if use_federation else client.get_parameters()),
                    config
                )
                
                client_params.append(params)
                round_metrics.append(metrics)
                all_metrics.append(metrics)
            
            # Federation step
            if use_federation and server:
                server.global_params = fedavg_aggregate(client_params)
                global_rules = server.consensus.get_global_rules()
                for client in clients:
                    client.receive_global_rules(global_rules)
        
        results = ScenarioResults(
            scenario_name=f"{scenario}_{'fed' if use_federation else 'nofed'}",
            num_rounds=num_rounds,
            num_clients=len(clients),
            use_federation=use_federation,
            round_metrics=all_metrics,
            timestamp=datetime.now().isoformat()
        )
        
        return results
    
    def export_results(self, results: ScenarioResults):
        """Export results to CSV and JSON"""
        
        # CSV
        csv_path = os.path.join(self.output_dir, f"scenario_{results.scenario_name}.csv")
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['round', 'client', 'accuracy', 'precision', 'recall', 
                           'f1', 'tp', 'fp', 'tn', 'fn', 'rules', 'global_rules'])
            for m in results.round_metrics:
                writer.writerow([m.round_num, m.client_id, f"{m.accuracy:.4f}",
                               f"{m.precision:.4f}", f"{m.recall:.4f}", f"{m.f1_score:.4f}",
                               m.true_positives, m.false_positives, m.true_negatives,
                               m.false_negatives, m.rules_generated, m.global_rules_received])
        
        print(f"Exported: {csv_path}")
        return csv_path


def run_comparison():
    """Run comparison: Federation vs No Federation"""
    
    print("\n" + "="*60)
    print("ENHANCED EXPERIMENTS: FEDERATION vs NO FEDERATION")
    print("="*60)
    
    runner = EnhancedExperimentRunner()
    all_results = {}
    
    # Scenarios to test
    scenarios = ['iid', 'non_iid', 'zero_day']
    
    for scenario in scenarios:
        # Run WITHOUT federation (baseline)
        print(f"\n[Baseline] {scenario.upper()} - No Federation")
        results_nofed = runner.run_scenario(scenario, num_rounds=8, use_federation=False)
        runner.export_results(results_nofed)
        all_results[f"{scenario}_nofed"] = results_nofed
        
        # Run WITH federation
        print(f"\n[Federated] {scenario.upper()} - With Federation")
        results_fed = runner.run_scenario(scenario, num_rounds=8, use_federation=True)
        runner.export_results(results_fed)
        all_results[f"{scenario}_fed"] = results_fed
    
    # Save summary
    summary = {}
    for name, results in all_results.items():
        final = results.get_final_metrics()
        summary[name] = {
            'accuracy': final.get('avg_accuracy', 0),
            'precision': final.get('avg_precision', 0),
            'recall': final.get('avg_recall', 0),
            'f1': final.get('avg_f1', 0),
            'total_rules': final.get('total_rules', 0),
        }
    
    summary_path = os.path.join(runner.output_dir, "enhanced_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Print comparison
    print("\n" + "="*60)
    print("RESULTS COMPARISON")
    print("="*60)
    
    for scenario in scenarios:
        nofed = summary.get(f"{scenario}_nofed", {})
        fed = summary.get(f"{scenario}_fed", {})
        
        print(f"\n{scenario.upper()}:")
        print(f"  No Federation:  Acc={nofed.get('accuracy',0):.1%}, F1={nofed.get('f1',0):.1%}")
        print(f"  With Federation: Acc={fed.get('accuracy',0):.1%}, F1={fed.get('f1',0):.1%}")
        
        acc_imp = fed.get('accuracy', 0) - nofed.get('accuracy', 0)
        f1_imp = fed.get('f1', 0) - nofed.get('f1', 0)
        print(f"  Improvement:     Acc={acc_imp:+.1%}, F1={f1_imp:+.1%}")
    
    print(f"\nResults saved to: {runner.output_dir}/")
    
    return all_results


def main():
    parser = argparse.ArgumentParser(description='Enhanced Experiment Runner')
    parser.add_argument('--scenario', choices=['iid', 'non_iid', 'zero_day'])
    parser.add_argument('--rounds', type=int, default=8)
    parser.add_argument('--no-federation', action='store_true', help='Run without federation')
    
    args = parser.parse_args()
    
    runner = EnhancedExperimentRunner()
    
    if args.scenario:
        results = runner.run_scenario(args.scenario, args.rounds, 
                                      use_federation=not args.no_federation)
        runner.export_results(results)
    else:
        run_comparison()


if __name__ == "__main__":
    main()

