#!/usr/bin/env python3
"""
Federated NIDS - Day 3: Enhanced Federated Client with Data Loading
Enhanced client that loads packet data and integrates with consensus server
"""

import os
import sys
import time
import json
import logging
import requests
from typing import Dict, Any, List, Optional, Tuple

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from federated.client import MinimalFederatedClient
from federated.packet_replay import ClientPacketManager
from closed_loop import ClosedLoopNIDS

logger = logging.getLogger(__name__)


class EnhancedFederatedClient(MinimalFederatedClient):
    """
    Enhanced Federated Client with real packet data loading.
    
    Features:
    - Loads packet partitions from files
    - Processes packets per federated round
    - Submits rules to consensus server
    - Receives global rules
    - Tracks detailed metrics
    """
    
    def __init__(
        self,
        cid: str,
        data_file: str = None,
        consensus_server_url: str = "http://localhost:5000",
        nids_config: Optional[Dict[str, Any]] = None,
        rules_dir: str = "federated/rules",
        packets_per_round: int = 500,
    ):
        """
        Initialize enhanced federated client.
        
        Args:
            cid: Client identifier
            data_file: Path to packet data file
            consensus_server_url: URL of consensus server
            nids_config: NIDS configuration
            rules_dir: Directory for local rules
            packets_per_round: Packets to process per federated round
        """
        # Initialize parent
        super().__init__(
            cid=cid,
            nids_config=nids_config,
            rules_dir=rules_dir,
            simulate_traffic=False,  # Use real data
            traffic_pattern="normal"
        )
        
        self.consensus_server_url = consensus_server_url
        self.packets_per_round = packets_per_round
        
        # Data loading
        self.packet_manager = None
        if data_file:
            self.load_data(data_file)
        
        # Round tracking
        self.current_round = 0
        self.total_packets_processed = 0
        
        # Metrics
        self.round_metrics = []
        
        # Global rules received
        self.global_rules = []
        self.last_global_rules_hash = ""
        
        print(f"\n[{cid}] Enhanced client initialized")
        print(f"  Data file: {data_file}")
        print(f"  Consensus server: {consensus_server_url}")
        print(f"  Packets per round: {packets_per_round}")
    
    def load_data(self, filepath: str) -> None:
        """Load packet data from file."""
        self.packet_manager = ClientPacketManager(self.cid, filepath)
        
        # Get stats
        stats = self.packet_manager.get_partition_stats()
        
        print(f"\n[{self.cid}] Data loaded:")
        print(f"  Total packets: {stats['total_packets']}")
        print(f"  Attack %: {stats['attack_percentage']:.1f}%")
        print(f"  Top attacks: {dict(list(stats['attack_distribution'].items())[:3])}")
    
    def process_round_packets(self, round_num: int) -> Dict[str, Any]:
        """
        Process packets for a federated round.
        
        Args:
            round_num: Round number
            
        Returns:
            Processing results
        """
        if not self.packet_manager:
            return {'error': 'No data loaded'}
        
        # Get packets for this round
        packets = self.packet_manager.get_packets_for_round(
            round_num, 
            self.packets_per_round
        )
        
        if not packets:
            return {'error': 'No packets available', 'processed': 0}
        
        results = {
            'round': round_num,
            'packets_processed': 0,
            'anomalies_detected': 0,
            'rules_generated': 0,
            'attack_packets_seen': 0,
            'normal_packets_seen': 0,
        }
        
        # Process each packet
        for packet in packets:
            try:
                # Track attack vs normal
                if packet.get('attack_type'):
                    results['attack_packets_seen'] += 1
                else:
                    results['normal_packets_seen'] += 1
                
                # Process through NIDS
                anomaly = self.nids.process_packet(packet)
                
                results['packets_processed'] += 1
                
                # If anomaly detected, try to generate rule
                if anomaly is not None:
                    results['anomalies_detected'] += 1
                    
                    rule = self.nids.rule_generator.generate_rule(anomaly)
                    if rule:
                        results['rules_generated'] += 1
                        
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
        
        # Update tracking
        self.total_packets_processed += results['packets_processed']
        self.current_round = round_num
        
        # Store metrics
        self.round_metrics.append({
            **results,
            'timestamp': time.time(),
        })
        
        print(f"\n[{self.cid}] Round {round_num} complete:")
        print(f"  Packets: {results['packets_processed']}")
        print(f"  Anomalies: {results['anomalies_detected']}")
        print(f"  Rules: {results['rules_generated']}")
        
        return results
    
    def submit_rules_to_server(self) -> Dict[str, Any]:
        """
        Submit generated rules to consensus server.
        
        Returns:
            Submission results
        """
        # Get local rules
        local_rules = self.nids.rule_generator.get_all_rules()
        
        if not local_rules:
            return {'status': 'no_rules', 'submitted': 0}
        
        # Convert to submission format
        rules_to_submit = []
        for rule in local_rules[-10:]:  # Submit last 10 rules
            rules_to_submit.append({
                'rule_string': rule.get('rule_string', ''),
                'anomaly_type': rule.get('anomaly_type', ''),
                'src_ip': rule.get('src_ip', ''),
                'dst_port': rule.get('dst_port', 'any'),
                'score': rule.get('score', 0.5),
            })
        
        # Submit to server
        try:
            response = requests.post(
                f"{self.consensus_server_url}/api/federated/submit_rules",
                json={
                    'client_id': self.cid,
                    'rules': rules_to_submit
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"\n[{self.cid}] Rules submitted:")
                print(f"  Submitted: {result.get('rules_submitted', 0)}")
                print(f"  Promoted: {result.get('rules_promoted', 0)}")
                return result
            else:
                return {'error': f'Server error: {response.status_code}'}
                
        except requests.exceptions.ConnectionError:
            return {'error': 'Cannot connect to server'}
        except Exception as e:
            return {'error': str(e)}
    
    def fetch_global_rules(self) -> List[Dict[str, Any]]:
        """
        Fetch global rules from consensus server.
        
        Returns:
            List of global rules
        """
        try:
            response = requests.get(
                f"{self.consensus_server_url}/api/federated/global_rules",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                rules = result.get('global_rules', [])
                
                # Check for new rules
                current_hash = json.dumps([r.get('rule_hash', '') for r in rules])
                if current_hash != self.last_global_rules_hash:
                    new_count = len(rules) - len(self.global_rules)
                    if new_count > 0:
                        print(f"\n[{self.cid}] Received {new_count} new global rule(s)!")
                    
                    self.global_rules = rules
                    self.last_global_rules_hash = current_hash
                
                return rules
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error fetching global rules: {e}")
            return []
    
    def fit_with_data(
        self,
        parameters: List[Any],
        config: Dict[str, Any]
    ) -> Tuple[List[Any], int, Dict[str, Any]]:
        """
        Perform fit with real packet data.
        
        Overrides parent fit method to use real data.
        
        Args:
            parameters: Current global parameters
            config: Fit configuration
            
        Returns:
            Tuple of (updated parameters, num_samples, metrics)
        """
        round_num = config.get('round_number', 0)
        
        print(f"\n{'='*60}")
        print(f"[{self.cid}] FIT ROUND {round_num}")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        # 1. Apply global parameters if provided
        if parameters is not None:
            self.set_parameters(parameters)
        
        # 2. Process packets for this round
        round_results = self.process_round_packets(round_num)
        
        # 3. Save local rules
        self._save_local_rules()
        
        # 4. Submit rules to consensus server
        submission_result = self.submit_rules_to_server()
        
        # 5. Fetch global rules
        global_rules = self.fetch_global_rules()
        
        # 6. Get updated parameters
        updated_params = self.get_parameters()
        
        elapsed = time.time() - start_time
        
        # Build metrics
        metrics = {
            'loss': 1.0 - (round_results.get('anomalies_detected', 0) / max(1, round_results.get('packets_processed', 1))),
            'packets_processed': round_results.get('packets_processed', 0),
            'anomalies_detected': round_results.get('anomalies_detected', 0),
            'rules_generated': round_results.get('rules_generated', 0),
            'attack_packets_seen': round_results.get('attack_packets_seen', 0),
            'normal_packets_seen': round_results.get('normal_packets_seen', 0),
            'global_rules_received': len(global_rules),
            'fit_time': elapsed,
        }
        
        print(f"\n[{self.cid}] Round {round_num} metrics:")
        print(f"  Packets: {metrics['packets_processed']}")
        print(f"  Anomalies: {metrics['anomalies_detected']}")
        print(f"  Rules generated: {metrics['rules_generated']}")
        print(f"  Global rules: {metrics['global_rules_received']}")
        print(f"  Time: {elapsed:.2f}s")
        
        return (
            updated_params, 
            round_results.get('packets_processed', 0), 
            metrics
        )
    
    def save_metrics(self, filepath: str) -> None:
        """Save client metrics to file."""
        data = {
            'client_id': self.cid,
            'current_round': self.current_round,
            'total_packets_processed': self.total_packets_processed,
            'round_metrics': self.round_metrics,
            'global_rules_received': len(self.global_rules),
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[{self.cid}] Metrics saved to {filepath}")


# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

def create_enhanced_client(
    cid: str,
    data_file: str,
    consensus_server_url: str = "http://localhost:5000",
    packets_per_round: int = 500,
    nids_config: Optional[Dict] = None
) -> EnhancedFederatedClient:
    """
    Factory function to create enhanced federated client.
    
    Args:
        cid: Client identifier
        data_file: Path to packet data
        consensus_server_url: Consensus server URL
        packets_per_round: Packets per round
        nids_config: NIDS config
        
    Returns:
        EnhancedFederatedClient instance
    """
    return EnhancedFederatedClient(
        cid=cid,
        data_file=data_file,
        consensus_server_url=consensus_server_url,
        nids_config=nids_config,
        packets_per_round=packets_per_round,
    )


# ============================================================================
# TEST
# ============================================================================

if __name__ == '__main__':
    print("Testing Enhanced Federated Client...")
    
    # First generate some test data
    from federated.dataset_generator import generate_client_partition
    import tempfile
    
    # Create temp data file
    packets = generate_client_partition(
        client_id='test_client',
        num_packets=1000,
        attack_focus='port_scan',
        attack_ratio=0.3
    )
    
    # Save to temp file
    import json
    temp_dir = tempfile.mkdtemp()
    temp_file = os.path.join(temp_dir, 'test_packets.json')
    
    with open(temp_file, 'w') as f:
        json.dump({
            'metadata': {'num_packets': len(packets)},
            'packets': packets
        }, f)
    
    # Create client
    client = EnhancedFederatedClient(
        cid='test_client',
        data_file=temp_file,
        consensus_server_url='http://localhost:5000',
        packets_per_round=200
    )
    
    # Test round processing
    print("\n--- Testing round processing ---")
    results = client.process_round_packets(0)
    print(f"Round results: {results}")
    
    # Test with fit
    print("\n--- Testing fit_with_data ---")
    params = client.get_parameters()
    new_params, num_samples, metrics = client.fit_with_data(
        params, 
        {'round_number': 1}
    )
    print(f"Fit metrics: {metrics}")
    
    print("\n✓ Enhanced client test complete!")

