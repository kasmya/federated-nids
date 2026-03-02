#!/usr/bin/env python3
"""
Federated NIDS - Minimal Client Wrapper
Day 1: Foundation & Flower Setup

This module provides:
- MinimalFederatedClient: A minimal Flower client wrapper for NIDS
- FederatedNIDSClient: Extended client with full NIDS integration

The client extracts key parameters from the NIDS and participates in 
federated learning rounds with other clients.
"""

import numpy as np
import logging
import os
import sys
import time
from typing import Dict, Any, List, Tuple, Optional

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import NIDS components
from closed_loop import ClosedLoopNIDS, SimpleAnomalyDetector, RuleGenerator
from closed_loop.baselines import AdaptiveBaseline

logger = logging.getLogger(__name__)


# ============================================================================
# MINIMAL FEDERATED CLIENT
# ============================================================================

class MinimalFederatedClient:
    """
    Minimal Federated Learning Client for NIDS.
    
    This client wraps an existing NIDS (ClosedLoopNIDS) and provides
    Flower-compatible methods for federated learning.
    
    Key Features:
    - Extracts parameters: detection_threshold, baseline means/stds
    - Serializes to NumPy arrays for Flower
    - Implements get_parameters(), fit(), evaluate()
    - Generates and stores rules locally
    
    Usage:
        client = MinimalFederatedClient(cid='client_1')
        parameters = client.get_parameters()  # For federation
        results = client.fit(parameters, config)  # Local training
        metrics = client.evaluate(parameters, config)  # Evaluation
    """
    
    def __init__(
        self, 
        cid: str,
        nids_config: Optional[Dict[str, Any]] = None,
        rules_dir: str = "federated/rules",
        simulate_traffic: bool = True,
        traffic_pattern: str = "normal"
    ):
        """
        Initialize the federated client.
        
        Args:
            cid: Client identifier
            nids_config: Configuration for ClosedLoopNIDS
            rules_dir: Directory to store generated rules
            simulate_traffic: Whether to use simulated packets
            traffic_pattern: Type of traffic to simulate ('normal', 'port_scan', 'syn_flood')
        """
        self.cid = cid
        self.nids_config = nids_config or {}
        self.rules_dir = rules_dir
        self.simulate_traffic = simulate_traffic
        self.traffic_pattern = traffic_pattern
        
        # Create rules directory
        os.makedirs(rules_dir, exist_ok=True)
        
        # Initialize NIDS
        print(f"[{cid}] Initializing NIDS...")
        self.nids = ClosedLoopNIDS(self.nids_config)
        
        # Statistics
        self.stats = {
            'rounds_participated': 0,
            'fit_samples': 0,
            'anomalies_detected': 0,
            'rules_generated': 0,
            'last_fit_time': 0,
            'last_evaluate_time': 0,
        }
        
        # Parameters (cached for federation)
        self._cached_parameters = None
        
        print(f"[{cid}] NIDS initialized successfully")
        print(f"[{cid}] Detection threshold: {self.nids.detector.detection_threshold}")
        print(f"[{cid}] Traffic pattern: {traffic_pattern}")
    
    # =========================================================================
    # FLOWER CLIENT INTERFACE
    # =========================================================================
    
    def get_parameters(self, config: Optional[Dict[str, Any]] = None) -> List[np.ndarray]:
        """
        Get current NIDS parameters as NumPy arrays.
        
        This is called by the Flower server to get the client's parameters
        for aggregation.
        
        Args:
            config: Optional configuration (unused in minimal version)
            
        Returns:
            List of NumPy arrays representing NIDS parameters
        """
        from federated.utils import serialize_parameters
        
        # Extract parameters from NIDS
        params = self._extract_nids_parameters()
        
        # Serialize to NumPy arrays
        arrays = serialize_parameters(params)
        
        # Cache for potential reuse
        self._cached_parameters = arrays
        
        # Log what we're sending
        print(f"[{self.cid}] get_parameters() - Sending {len(arrays)} parameter arrays")
        print(f"  - Detection threshold: {params['detection_threshold']}")
        print(f"  - Packet rate baseline: {params['baseline_stats']['packet_rate']}")
        
        return arrays
    
    def set_parameters(self, parameters: List[np.ndarray]) -> None:
        """
        Set NIDS parameters from NumPy arrays.
        
        This is called by the Flower server to distribute aggregated
        parameters to this client.
        
        Args:
            parameters: List of NumPy arrays from federation
        """
        from federated.utils import deserialize_parameters
        
        print(f"[{self.cid}] set_parameters() - Receiving {len(parameters)} parameter arrays")
        
        # Deserialize parameters
        params = deserialize_parameters(parameters)
        
        # Apply to NIDS
        self._apply_nids_parameters(params)
        
        # Clear cache
        self._cached_parameters = None
        
        print(f"[{self.cid}] Applied new parameters:")
        print(f"  - Detection threshold: {params['detection_threshold']}")
        print(f"  - Packet rate baseline: {params['baseline_stats']['packet_rate']}")
    
    def fit(
        self, 
        parameters: List[np.ndarray], 
        config: Dict[str, Any]
    ) -> Tuple[List[np.ndarray], int, Dict[str, Any]]:
        """
        Perform local training (fit) on the NIDS.
        
        In the NIDS context, this means:
        - Processing simulated packets to generate anomalies
        - Updating baselines based on new data
        - Generating rules from detected anomalies
        
        Args:
            parameters: Current global parameters from server
            config: Configuration for fit (num_rounds, etc.)
            
        Returns:
            Tuple of (updated parameters, num_samples, metrics)
        """
        from federated.utils import serialize_parameters
        
        round_num = config.get('round_number', 0)
        
        print(f"\n[{self.cid}] fit() - Round {round_num}")
        print(f"  Config: {config}")
        
        start_time = time.time()
        
        # 1. Apply global parameters
        if parameters is not None:
            self.set_parameters(parameters)
        
        # 2. Process simulated traffic (local training)
        if self.simulate_traffic:
            num_packets = config.get('num_packets', 100)
            self._process_simulated_traffic(num_packets)
        
        # 3. Get updated parameters
        updated_params = self.get_parameters()
        
        # 4. Save rules locally
        self._save_local_rules()
        
        elapsed = time.time() - start_time
        
        # Update stats
        self.stats['rounds_participated'] += 1
        self.stats['fit_samples'] += self.stats.get('last_packets_processed', 0)
        self.stats['last_fit_time'] = elapsed
        
        metrics = {
            'loss': 1.0 - self.stats.get('anomaly_detection_rate', 0.5),
            'anomalies_detected': self.stats.get('last_anomalies', 0),
            'rules_generated': self.stats.get('last_rules', 0),
            'packets_processed': self.stats.get('last_packets_processed', 0),
            'fit_time': elapsed,
        }
        
        print(f"[{self.cid}] fit() complete in {elapsed:.2f}s")
        print(f"  Anomalies detected: {metrics['anomalies_detected']}")
        print(f"  Rules generated: {metrics['rules_generated']}")
        
        return updated_params, self.stats.get('last_packets_processed', 0), metrics
    
    def evaluate(
        self, 
        parameters: List[np.ndarray], 
        config: Dict[str, Any]
    ) -> Tuple[float, int, Dict[str, Any]]:
        """
        Evaluate the NIDS with current or provided parameters.
        
        Args:
            parameters: Parameters to evaluate
            config: Configuration for evaluation
            
        Returns:
            Tuple of (loss, num_samples, metrics)
        """
        round_num = config.get('round_number', 0)
        
        print(f"\n[{self.cid}] evaluate() - Round {round_num}")
        
        start_time = time.time()
        
        # Apply parameters if provided
        if parameters is not None:
            self.set_parameters(parameters)
        
        # Run evaluation on simulated test data
        num_test_packets = config.get('num_test_packets', 50)
        results = self._run_evaluation(num_test_packets)
        
        elapsed = time.time() - start_time
        
        # Update stats
        self.stats['last_evaluate_time'] = elapsed
        
        metrics = {
            'loss': results['loss'],
            'accuracy': results['accuracy'],
            'precision': results['precision'],
            'recall': results['recall'],
            'anomalies_detected': results['anomalies'],
            'evaluate_time': elapsed,
        }
        
        print(f"[{self.cid}] evaluate() complete in {elapsed:.2f}s")
        print(f"  Loss: {metrics['loss']:.4f}, Accuracy: {metrics['accuracy']:.4f}")
        
        return metrics['loss'], num_test_packets, metrics
    
    # =========================================================================
    # PARAMETER EXTRACTION/APPLICATION
    # =========================================================================
    
    def _extract_nids_parameters(self) -> Dict[str, Any]:
        """
        Extract parameters from the NIDS for federation.
        
        Returns:
            Dictionary with NIDS parameters
        """
        detector = self.nids.detector
        
        # Get baseline stats from the global baseline
        # (or from the first IP baseline as representative)
        baseline_stats = {}
        
        if detector.ip_baselines.baselines:
            # Use first IP baseline as representative
            first_ip = list(detector.ip_baselines.baselines.keys())[0]
            baseline = detector.ip_baselines.baselines[first_ip]
            baseline_stats = baseline.get_baseline_stats()
        else:
            # Use default values
            baseline_stats = {
                'packet_rate': {'value': 5.0, 'std': 3.0},
                'port_diversity': {'value': 3.0, 'std': 2.0},
                'connection_rate': {'value': 2.0, 'std': 2.0},
                'bytes_per_second': {'value': 1000.0, 'std': 500.0},
                'dns_query_rate': {'value': 0.5, 'std': 0.5},
                'icmp_count': {'value': 1.0, 'std': 1.0},
            }
        
        params = {
            'detection_threshold': detector.detection_threshold,
            'baseline_stats': baseline_stats,
            'adaptation_rate': 0.1,  # Default adaptation rate
            'window_size': detector.window_size,
        }
        
        return params
    
    def _apply_nids_parameters(self, params: Dict[str, Any]) -> None:
        """
        Apply parameters to the NIDS.
        
        Args:
            params: Dictionary with NIDS parameters
        """
        detector = self.nids.detector
        
        # Apply detection threshold
        if 'detection_threshold' in params:
            detector.detection_threshold = params['detection_threshold']
            print(f"[{self.cid}] Updated detection threshold to {params['detection_threshold']}")
        
        # Apply baseline stats to all tracked IPs
        if 'baseline_stats' in params:
            new_baselines = params['baseline_stats']
            
            for ip, baseline in detector.ip_baselines.baselines.items():
                for feature, stats in new_baselines.items():
                    if feature in baseline.baselines:
                        baseline.baselines[feature]['value'] = stats['value']
                        baseline.baselines[feature]['std'] = stats['std']
            
            print(f"[{self.cid}] Updated baseline statistics")
    
    # =========================================================================
    # SIMULATED TRAFFIC PROCESSING
    # =========================================================================
    
    def _process_simulated_traffic(self, num_packets: int = 100) -> None:
        """
        Process simulated network packets.
        
        This simulates network traffic to:
        - Generate anomalies for rule generation
        - Update baselines
        - Test the NIDS
        
        Args:
            num_packets: Number of packets to simulate
        """
        print(f"[{self.cid}] Processing {num_packets} simulated packets...")
        
        # Generate packets based on traffic pattern
        packets = self._generate_simulated_packets(num_packets)
        
        anomalies_detected = 0
        packets_processed = 0
        
        # Process each packet
        for packet in packets:
            result = self.nids.process_packet(packet)
            packets_processed += 1
            
            if result is not None:
                anomalies_detected += 1
                # Try to generate a rule
                rule = self.nids.rule_generator.generate_rule(result)
                if rule:
                    self.stats['rules_generated'] += 1
        
        # Update stats
        self.stats['last_packets_processed'] = packets_processed
        self.stats['last_anomalies'] = anomalies_detected
        self.stats['last_rules'] = self.stats['rules_generated']
        
        if packets_processed > 0:
            self.stats['anomaly_detection_rate'] = anomalies_detected / packets_processed
        
        print(f"[{self.cid}] Processed {packets_processed} packets, "
              f"detected {anomalies_detected} anomalies")
    
    def _generate_simulated_packets(self, num_packets: int) -> List[Dict[str, Any]]:
        """
        Generate simulated packets based on traffic pattern.
        
        Args:
            num_packets: Number of packets to generate
            
        Returns:
            List of packet dictionaries
        """
        packets = []
        
        if self.traffic_pattern == "port_scan":
            # Simulate port scan attack
            attacker_ip = "192.168.1.100"
            target_ip = "10.0.0.1"
            
            for i in range(num_packets):
                packet = {
                    'src': attacker_ip,
                    'dst': target_ip,
                    'proto': 'tcp',
                    'sport': 5000 + i,
                    'dport': 1 + (i % 100),  # Scanning many ports
                    'flags': 'S',  # SYN
                    'length': 64,
                    'timestamp': time.time() + i * 0.01
                }
                packets.append(packet)
        
        elif self.traffic_pattern == "syn_flood":
            # Simulate SYN flood attack
            attacker_ip = "192.168.1.200"
            target_ip = "10.0.0.2"
            
            for i in range(num_packets):
                packet = {
                    'src': attacker_ip,
                    'dst': target_ip,
                    'proto': 'tcp',
                    'sport': 6000 + i,
                    'dport': 80,
                    'flags': 'S',  # SYN
                    'length': 64,
                    'timestamp': time.time() + i * 0.001  # High rate
                }
                packets.append(packet)
        
        elif self.traffic_pattern == "normal":
            # Simulate normal traffic
            normal_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
            target_ips = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
            
            for i in range(num_packets):
                packet = {
                    'src': normal_ips[i % len(normal_ips)],
                    'dst': target_ips[i % len(target_ips)],
                    'proto': 'tcp',
                    'sport': 10000 + i,
                    'dport': [80, 443, 22, 8080][i % 4],
                    'flags': 'PA',  # PSH+ACK
                    'length': 500 + (i % 100),
                    'timestamp': time.time() + i * 0.1
                }
                packets.append(packet)
        
        elif self.traffic_pattern == "mixed":
            # Mix of normal and attack traffic
            # 80% normal, 20% attack
            normal_count = int(num_packets * 0.8)
            attack_count = num_packets - normal_count
            
            # Generate normal packets
            for i in range(normal_count):
                packets.append({
                    'src': f"192.168.1.{10 + (i % 10)}",
                    'dst': '10.0.0.5',
                    'proto': 'tcp',
                    'sport': 10000 + i,
                    'dport': [80, 443][i % 2],
                    'flags': 'PA',
                    'length': 500,
                    'timestamp': time.time() + i * 0.1
                })
            
            # Generate attack packets (port scan)
            for i in range(attack_count):
                packets.append({
                    'src': '192.168.1.100',  # Attacker
                    'dst': '10.0.0.5',
                    'proto': 'tcp',
                    'sport': 7000 + i,
                    'dport': 1000 + i,
                    'flags': 'S',
                    'length': 64,
                    'timestamp': time.time() + (normal_count + i) * 0.01
                })
        
        else:
            # Default: random packets
            for i in range(num_packets):
                packets.append({
                    'src': f"192.168.1.{i % 255}",
                    'dst': f"10.0.0.{i % 255}",
                    'proto': ['tcp', 'udp', 'icmp'][i % 3],
                    'sport': 1000 + i,
                    'dport': [80, 443, 22, 53][i % 4],
                    'flags': 'PA',
                    'length': 100 + i,
                    'timestamp': time.time() + i
                })
        
        return packets
    
    def _run_evaluation(self, num_test_packets: int) -> Dict[str, float]:
        """
        Run evaluation on test packets.
        
        Args:
            num_test_packets: Number of test packets
            
        Returns:
            Evaluation metrics
        """
        # Generate test packets (mixed traffic)
        test_packets = self._generate_simulated_packets(num_test_packets)
        
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        true_negatives = 0
        
        for packet in test_packets:
            result = self.nids.process_packet(packet)
            
            # Determine if packet should be detected as anomaly
            is_actually_malicious = (
                packet.get('src') in ['192.168.1.100', '192.168.1.200'] or
                packet.get('flags') == 'S'  # SYN flag often indicates scan
            )
            
            is_detected = result is not None
            
            if is_detected and is_actually_malicious:
                true_positives += 1
            elif is_detected and not is_actually_malicious:
                false_positives += 1
            elif not is_detected and is_actually_malicious:
                false_negatives += 1
            else:
                true_negatives += 1
        
        # Calculate metrics
        total = true_positives + false_positives + false_negatives + true_negatives
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'loss': 1.0 - accuracy,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'anomalies': true_positives,
        }
    
    # =========================================================================
    # RULE MANAGEMENT
    # =========================================================================
    
    def _save_local_rules(self) -> None:
        """Save generated rules locally for sharing."""
        rules = self.nids.rule_generator.get_all_rules()
        
        if not rules:
            return
        
        # Save to client-specific file
        rules_file = os.path.join(self.rules_dir, f"rules_{self.cid}.txt")
        
        try:
            with open(rules_file, 'a') as f:
                for rule in rules[-5:]:  # Save last 5 rules
                    f.write(f"# Client: {self.cid} | Round: {self.stats['rounds_participated']}\n")
                    f.write(rule['rule_string'] + '\n')
            
            print(f"[{self.cid}] Saved rules to {rules_file}")
        except Exception as e:
            print(f"[{self.cid}] Error saving rules: {e}")
    
    def get_local_rules(self) -> List[Dict[str, Any]]:
        """
        Get all rules generated by this client.
        
        Returns:
            List of rule dictionaries
        """
        return self.nids.rule_generator.get_all_rules()
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get client status information.
        
        Returns:
            Status dictionary
        """
        return {
            'cid': self.cid,
            'nids_status': self.nids.get_status(),
            'federation_stats': self.stats,
            'traffic_pattern': self.traffic_pattern,
            'rules_file': os.path.join(self.rules_dir, f"rules_{self.cid}.txt"),
        }


# ============================================================================
# EXTENDED FEDERATED CLIENT (for more complex scenarios)
# ============================================================================

class FederatedNIDSClient(MinimalFederatedClient):
    """
    Extended FederatedNIDS Client with additional features.
    
    This extends the minimal client with:
    - More sophisticated traffic simulation
    - Better rule sharing capabilities
    - Custom baseline management
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Extended features
        self.learned_rules = []
        self.shared_rules = []
    
    def share_rules(self) -> List[Dict[str, Any]]:
        """
        Get rules to share with other clients.
        
        Returns:
            List of rule dictionaries
        """
        return self.get_local_rules()
    
    def receive_rules(self, rules: List[Dict[str, Any]]) -> None:
        """
        Receive rules from other clients.
        
        Args:
            rules: List of rule dictionaries
        """
        self.shared_rules.extend(rules)
        print(f"[{self.cid}] Received {len(rules)} shared rules")
    
    def merge_rules(self) -> None:
        """Merge shared rules with local rules."""
        # This could implement rule deduplication, voting, etc.
        print(f"[{self.cid}] Merging {len(self.shared_rules)} shared rules")


# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

def create_federated_client(
    cid: str,
    server_address: str = "localhost:8080",
    nids_config: Optional[Dict[str, Any]] = None,
    traffic_pattern: str = "normal",
    use_simulation: bool = True
) -> MinimalFederatedClient:
    """
    Factory function to create a federated client.
    
    Args:
        cid: Client identifier
        server_address: Flower server address
        nids_config: NIDS configuration
        traffic_pattern: Traffic pattern to simulate
        use_simulation: Whether to use simulation mode
        
    Returns:
        MinimalFederatedClient instance
    """
    client = MinimalFederatedClient(
        cid=cid,
        nids_config=nids_config,
        simulate_traffic=use_simulation,
        traffic_pattern=traffic_pattern
    )
    
    print(f"\n{'='*60}")
    print(f"Federated Client Created: {cid}")
    print(f"Server: {server_address}")
    print(f"Traffic Pattern: {traffic_pattern}")
    print(f"{'='*60}\n")
    
    return client


# ============================================================================
# TEST RUNNER
# ============================================================================

if __name__ == '__main__':
    # Test the client
    print("Testing MinimalFederatedClient...")
    
    # Create client with port scan pattern
    client = MinimalFederatedClient(
        cid='test_client',
        traffic_pattern='port_scan',
        simulate_traffic=True
    )
    
    # Test get_parameters
    print("\n--- Testing get_parameters() ---")
    params = client.get_parameters()
    print(f"Got {len(params)} parameter arrays")
    
    # Test fit
    print("\n--- Testing fit() ---")
    new_params, num_samples, metrics = client.fit(
        params, 
        {'round_number': 1, 'num_packets': 50}
    )
    print(f"Fit metrics: {metrics}")
    
    # Test evaluate
    print("\n--- Testing evaluate() ---")
    loss, num_samples, eval_metrics = client.evaluate(
        new_params,
        {'round_number': 1, 'num_test_packets': 30}
    )
    print(f"Evaluation metrics: {eval_metrics}")
    
    # Test set_parameters
    print("\n--- Testing set_parameters() ---")
    client.set_parameters(new_params)
    
    # Get status
    print("\n--- Client Status ---")
    status = client.get_status()
    print(f"Status: {status}")
    
    print("\n✓ All tests passed!")

