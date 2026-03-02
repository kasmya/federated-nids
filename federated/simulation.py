#!/usr/bin/env python3
"""
Federated NIDS - Client Simulator
Day 1: Foundation & Flower Setup

This module provides:
- PacketSimulator: Generate simulated network packets
- ClientSimulator: Run multiple client instances
- run_simulation: Complete simulation runner
"""

import numpy as np
import logging
import os
import sys
import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)


# ============================================================================
# TRAFFIC PATTERNS
# ============================================================================

class TrafficPattern(Enum):
    """Types of simulated traffic patterns."""
    NORMAL = "normal"
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    MIXED = "mixed"


@dataclass
class PacketTemplate:
    """Template for generating packets."""
    src_ips: List[str]
    dst_ips: List[str]
    protocols: List[str]
    ports: List[int]
    flags: List[str]
    packet_rate: float  # packets per second
    anomaly_ratio: float  # ratio of anomalous packets


# ============================================================================
# PACKET SIMULATOR
# ============================================================================

class PacketSimulator:
    """
    Simulates network traffic for testing NIDS.
    
    This generates various types of network packets including:
    - Normal traffic
    - Port scan attacks
    - SYN flood attacks
    - Mixed traffic
    
    Usage:
        simulator = PacketSimulator(pattern=TrafficPattern.PORT_SCAN)
        packet = simulator.generate_packet()
        packets = simulator.generate_batch(100)
    """
    
    # Default templates for different patterns
    TEMPLATES = {
        TrafficPattern.NORMAL: PacketTemplate(
            src_ips=["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"],
            dst_ips=["10.0.0.10", "10.0.0.11", "10.0.0.12"],
            protocols=["tcp", "tcp", "tcp", "udp"],  # More TCP
            ports=[80, 443, 22, 8080, 53],
            flags=["PA", "PA", "PA", "S"],  # Most are data packets
            packet_rate=10.0,
            anomaly_ratio=0.0,
        ),
        TrafficPattern.PORT_SCAN: PacketTemplate(
            src_ips=["192.168.1.100"],  # Single attacker
            dst_ips=["10.0.0.1"],  # Single target
            protocols=["tcp"],
            ports=list(range(1, 1001)),  # Many ports
            flags=["S"],  # SYN scans
            packet_rate=50.0,
            anomaly_ratio=0.95,
        ),
        TrafficPattern.SYN_FLOOD: PacketTemplate(
            src_ips=["192.168.1.200", "192.168.1.201", "192.168.1.202"],  # Multiple attackers
            dst_ips=["10.0.0.2"],  # Single target
            protocols=["tcp"],
            ports=[80, 443],  # Web ports
            flags=["S"],  # SYN flood
            packet_rate=100.0,
            anomaly_ratio=0.98,
        ),
        TrafficPattern.DDOS: PacketTemplate(
            src_ips=[f"10.1.{i}.{j}" for i in range(1, 10) for j in range(1, 20)],  # Botnet
            dst_ips=["10.0.0.3"],  # Target
            protocols=["tcp", "udp", "icmp"],
            ports=[80, 443, 53, 22],
            flags=["S", "PA", "A"],
            packet_rate=200.0,
            anomaly_ratio=0.90,
        ),
        TrafficPattern.BRUTE_FORCE: PacketTemplate(
            src_ips=["192.168.1.50"],  # Attacker
            dst_ips=["10.0.0.4"],  # Target
            protocols=["tcp"],
            ports=[22],  # SSH
            flags=["S", "PA"],  # SYN + data
            packet_rate=5.0,
            anomaly_ratio=0.80,
        ),
        TrafficPattern.MIXED: PacketTemplate(
            src_ips=["192.168.1.10", "192.168.1.11", "192.168.1.100"],  # Normal + attacker
            dst_ips=["10.0.0.10", "10.0.0.11", "10.0.0.12"],
            protocols=["tcp", "tcp", "tcp", "udp", "icmp"],
            ports=[80, 443, 22, 53, 8080],
            flags=["PA", "PA", "S", "A"],
            packet_rate=15.0,
            anomaly_ratio=0.20,  # 20% attack
        ),
    }
    
    def __init__(
        self,
        pattern: TrafficPattern = TrafficPattern.NORMAL,
        seed: Optional[int] = None
    ):
        """
        Initialize the packet simulator.
        
        Args:
            pattern: Type of traffic to simulate
            seed: Random seed for reproducibility
        """
        self.pattern = pattern
        self.template = self.TEMPLATES[pattern]
        
        # Random state
        if seed is not None:
            np.random.seed(seed)
        self.rng = np.random.default_rng(seed)
        
        # Counters
        self.packet_count = 0
        self.anomaly_count = 0
        
        # State for multi-packet generation
        self.port_scan_port = 1
        self.syn_flood_src_idx = 0
        
        print(f"[PacketSimulator] Initialized with pattern: {pattern.value}")
    
    def generate_packet(self) -> Dict[str, Any]:
        """
        Generate a single simulated packet.
        
        Returns:
            Packet dictionary
        """
        template = self.template
        
        # Select random values
        src_ip = self.rng.choice(template.src_ips)
        dst_ip = self.rng.choice(template.dst_ips)
        proto = self.rng.choice(template.protocols)
        
        # Handle pattern-specific generation
        if self.pattern == TrafficPattern.PORT_SCAN:
            # Increment port for port scan
            dport = self.port_scan_port
            self.port_scan_port = (self.port_scan_port % 1000) + 1
            flags = "S"
        elif self.pattern == TrafficPattern.SYN_FLOOD:
            # Rotate through source IPs
            src_ip = template.src_ips[self.syn_flood_src_idx % len(template.src_ips)]
            self.syn_flood_src_idx += 1
            dport = self.rng.choice(template.ports)
            flags = "S"
        else:
            dport = self.rng.choice(template.ports)
            flags = self.rng.choice(template.flags)
        
        sport = self.rng.integers(1024, 65535)
        length = self.rng.integers(64, 1500)
        
        # Create packet
        packet = {
            'src': src_ip,
            'dst': dst_ip,
            'proto': proto,
            'sport': int(sport),
            'dport': int(dport),
            'flags': flags,
            'length': int(length),
            'timestamp': time.time(),
            'pattern': self.pattern.value,
        }
        
        self.packet_count += 1
        
        return packet
    
    def generate_batch(self, num_packets: int) -> List[Dict[str, Any]]:
        """
        Generate a batch of packets.
        
        Args:
            num_packets: Number of packets to generate
            
        Returns:
            List of packet dictionaries
        """
        packets = []
        
        for _ in range(num_packets):
            packets.append(self.generate_packet())
        
        return packets
    
    def generate_timed_batch(
        self, 
        num_packets: int, 
        duration_seconds: float
    ) -> List[Dict[str, Any]]:
        """
        Generate packets with realistic timing.
        
        Args:
            num_packets: Number of packets to generate
            duration_seconds: Duration to spread packets over
            
        Returns:
            List of packet dictionaries
        """
        packets = []
        
        start_time = time.time()
        
        for i in range(num_packets):
            packet = self.generate_packet()
            # Adjust timestamp for realistic distribution
            packet['timestamp'] = start_time + (i * duration_seconds / num_packets)
            packets.append(packet)
        
        return packets
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get simulator statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            'pattern': self.pattern.value,
            'total_packets': self.packet_count,
            'packet_rate': self.template.packet_rate,
            'anomaly_ratio': self.template.anomaly_ratio,
        }


# ============================================================================
# CLIENT SIMULATOR
# ============================================================================

class ClientSimulator:
    """
    Simulates a federated NIDS client.
    
    This wraps a MinimalFederatedClient and provides:
    - Traffic generation
    - Anomaly detection
    - Rule generation
    - Local baseline updates
    
    Usage:
        simulator = ClientSimulator(
            cid='client_A',
            pattern=TrafficPattern.PORT_SCAN
        )
        simulator.run_fit_round()
    """
    
    def __init__(
        self,
        cid: str,
        pattern: TrafficPattern = TrafficPattern.NORMAL,
        nids_config: Optional[Dict[str, Any]] = None,
        rules_dir: str = "federated/rules",
        seed: Optional[int] = None
    ):
        """
        Initialize the client simulator.
        
        Args:
            cid: Client identifier
            pattern: Traffic pattern to simulate
            nids_config: NIDS configuration
            rules_dir: Directory for rules
            seed: Random seed
        """
        self.cid = cid
        self.pattern = pattern
        self.nids_config = nids_config or {}
        self.rules_dir = rules_dir
        self.seed = seed
        
        # Import client
        from federated.client import MinimalFederatedClient
        
        # Create the federated client
        self.client = MinimalFederatedClient(
            cid=cid,
            nids_config=self.nids_config,
            rules_dir=rules_dir,
            simulate_traffic=False,  # We'll control traffic
            traffic_pattern=pattern.value
        )
        
        # Create packet simulator
        self.packet_simulator = PacketSimulator(pattern=pattern, seed=seed)
        
        # Statistics
        self.stats = {
            'rounds_completed': 0,
            'total_packets': 0,
            'total_anomalies': 0,
            'total_rules': 0,
        }
        
        print(f"[ClientSimulator {cid}] Initialized with pattern: {pattern.value}")
    
    def generate_traffic(self, num_packets: int) -> List[Dict[str, Any]]:
        """
        Generate simulated traffic.
        
        Args:
            num_packets: Number of packets to generate
            
        Returns:
            List of packets
        """
        return self.packet_simulator.generate_batch(num_packets)
    
    def process_traffic(self, packets: List[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Process traffic through the NIDS.
        
        Args:
            packets: List of packets to process
            
        Returns:
            Tuple of (packets_processed, anomalies_detected)
        """
        anomalies = 0
        
        for packet in packets:
            result = self.client.nids.process_packet(packet)
            if result is not None:
                anomalies += 1
                # Try to generate a rule
                rule = self.client.nids.rule_generator.generate_rule(result)
                if rule:
                    self.stats['total_rules'] += 1
        
        self.stats['total_packets'] += len(packets)
        self.stats['total_anomalies'] += anomalies
        
        return len(packets), anomalies
    
    def run_fit_round(
        self, 
        parameters: Optional[List[np.ndarray]] = None,
        num_packets: int = 100,
        round_num: int = 1
    ) -> Tuple[List[np.ndarray], int, Dict[str, Any]]:
        """
        Run a single fit round.
        
        Args:
            parameters: Current global parameters
            num_packets: Number of packets to process
            round_num: Round number
            
        Returns:
            Tuple of (updated_params, num_samples, metrics)
        """
        print(f"\n[ClientSimulator {self.cid}] Running fit round {round_num}")
        
        # Generate and process traffic
        packets = self.generate_traffic(num_packets)
        self.process_traffic(packets)
        
        # Run fit
        new_params, num_samples, metrics = self.client.fit(
            parameters,
            {'round_number': round_num, 'num_packets': num_packets}
        )
        
        self.stats['rounds_completed'] += 1
        
        return new_params, num_samples, metrics
    
    def run_evaluate_round(
        self,
        parameters: List[np.ndarray],
        num_test_packets: int = 50,
        round_num: int = 1
    ) -> Tuple[float, int, Dict[str, Any]]:
        """
        Run a single evaluation round.
        
        Args:
            parameters: Parameters to evaluate
            num_test_packets: Number of test packets
            round_num: Round number
            
        Returns:
            Tuple of (loss, num_samples, metrics)
        """
        return self.client.evaluate(
            parameters,
            {'round_number': round_num, 'num_test_packets': num_test_packets}
        )
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get client simulator status.
        
        Returns:
            Status dictionary
        """
        return {
            'cid': self.cid,
            'pattern': self.pattern.value,
            'client_stats': self.client.stats,
            'simulator_stats': self.stats,
            'packet_stats': self.packet_simulator.get_statistics(),
        }


# ============================================================================
# MULTI-CLIENT SIMULATOR
# ============================================================================

class MultiClientSimulator:
    """
    Runs multiple client simulators simultaneously.
    
    Usage:
        simulator = MultiClientSimulator()
        simulator.add_client('client_A', TrafficPattern.PORT_SCAN)
        simulator.add_client('client_B', TrafficPattern.NORMAL)
        results = simulator.run_federation(num_rounds=3)
    """
    
    def __init__(
        self,
        rules_dir: str = "federated/rules"
    ):
        """
        Initialize multi-client simulator.
        
        Args:
            rules_dir: Directory for rules
        """
        self.rules_dir = rules_dir
        self.clients: Dict[str, ClientSimulator] = {}
        
        # Ensure rules directory exists
        os.makedirs(rules_dir, exist_ok=True)
        
        print("[MultiClientSimulator] Initialized")
    
    def add_client(
        self,
        cid: str,
        pattern: TrafficPattern,
        nids_config: Optional[Dict[str, Any]] = None,
        seed: Optional[int] = None
    ) -> ClientSimulator:
        """
        Add a client to the simulation.
        
        Args:
            cid: Client identifier
            pattern: Traffic pattern
            nids_config: NIDS config
            seed: Random seed
            
        Returns:
            Created ClientSimulator
        """
        simulator = ClientSimulator(
            cid=cid,
            pattern=pattern,
            nids_config=nids_config,
            rules_dir=self.rules_dir,
            seed=seed
        )
        
        self.clients[cid] = simulator
        print(f"[MultiClientSimulator] Added client: {cid} (pattern: {pattern.value})")
        
        return simulator
    
    def get_client(self, cid: str) -> Optional[ClientSimulator]:
        """Get a client by ID."""
        return self.clients.get(cid)
    
    def get_all_clients(self) -> List[ClientSimulator]:
        """Get all clients."""
        return list(self.clients.values())
    
    def run_federation(
        self,
        num_rounds: int = 3,
        num_packets_per_round: int = 100,
        num_test_packets: int = 50
    ) -> Dict[str, Any]:
        """
        Run federated learning simulation.
        
        Args:
            num_rounds: Number of federation rounds
            num_packets_per_round: Packets per client per round
            num_test_packets: Test packets per evaluation
            
        Returns:
            Results dictionary
        """
        from federated.utils import aggregate_parameters_fedavg
        
        print("\n" + "="*60)
        print("MULTI-CLIENT FEDERATION SIMULATION")
        print(f"Clients: {list(self.clients.keys())}")
        print(f"Rounds: {num_rounds}")
        print("="*60 + "\n")
        
        if not self.clients:
            raise ValueError("No clients added to simulation")
        
        # Get initial parameters from first client
        first_client = list(self.clients.values())[0]
        current_params = first_client.client.get_parameters()
        
        print(f"[Simulation] Initial parameters: {len(current_params)} arrays")
        
        round_history = []
        
        for round_num in range(1, num_rounds + 1):
            print(f"\n{'='*60}")
            print(f"ROUND {round_num}/{num_rounds}")
            print(f"{'='*60}")
            
            # Collect parameters from all clients
            client_params = []
            client_fit_results = []
            
            for cid, simulator in self.clients.items():
                print(f"\n[Simulation] Client {cid} fitting...")
                
                new_params, num_samples, metrics = simulator.run_fit_round(
                    parameters=current_params,
                    num_packets=num_packets_per_round,
                    round_num=round_num
                )
                
                client_params.append(new_params)
                client_fit_results.append({
                    'cid': cid,
                    'num_samples': num_samples,
                    'metrics': metrics
                })
            
            # Aggregate
            print(f"\n[Simulation] Aggregating {len(client_params)} client parameters...")
            current_params = aggregate_parameters_fedavg(client_params)
            
            # Evaluate
            print(f"\n[Simulation] Evaluating...")
            eval_results = []
            
            for cid, simulator in self.clients.items():
                loss, num_samples, metrics = simulator.run_evaluate_round(
                    parameters=current_params,
                    num_test_packets=num_test_packets,
                    round_num=round_num
                )
                
                eval_results.append({
                    'cid': cid,
                    'loss': loss,
                    'metrics': metrics
                })
            
            # Calculate averages
            avg_loss = sum(r['loss'] for r in eval_results) / len(eval_results)
            avg_accuracy = sum(r['metrics'].get('accuracy', 0) for r in eval_results) / len(eval_results)
            
            print(f"\n[Simulation] Round {round_num} Summary:")
            print(f"  Average Loss: {avg_loss:.4f}")
            print(f"  Average Accuracy: {avg_accuracy:.4f}")
            
            round_history.append({
                'round': round_num,
                'fit_results': client_fit_results,
                'eval_results': eval_results,
                'avg_loss': avg_loss,
                'avg_accuracy': avg_accuracy,
            })
        
        # Final results
        print("\n" + "="*60)
        print("SIMULATION COMPLETE")
        print("="*60)
        
        # Get final client statuses
        final_statuses = {cid: sim.get_status() for cid, sim in self.clients.items()}
        
        return {
            'status': 'complete',
            'num_rounds': num_rounds,
            'num_clients': len(self.clients),
            'round_history': round_history,
            'final_statuses': final_statuses,
            'final_parameters': current_params,
        }


# ============================================================================
# SIMPLE RUNNER FUNCTIONS
# ============================================================================

def run_simulation(
    client_configs: List[Dict[str, Any]],
    num_rounds: int = 3,
    num_packets: int = 100,
    num_test_packets: int = 50
) -> Dict[str, Any]:
    """
    Simple function to run a federation simulation.
    
    Args:
        client_configs: List of client configurations
            [{'cid': 'client_A', 'pattern': 'port_scan'}, ...]
        num_rounds: Number of rounds
        num_packets: Packets per round
        num_test_packets: Test packets
        
    Returns:
        Results dictionary
    """
    # Create multi-client simulator
    simulator = MultiClientSimulator()
    
    # Pattern mapping
    pattern_map = {
        'normal': TrafficPattern.NORMAL,
        'port_scan': TrafficPattern.PORT_SCAN,
        'syn_flood': TrafficPattern.SYN_FLOOD,
        'ddos': TrafficPattern.DDOS,
        'brute_force': TrafficPattern.BRUTE_FORCE,
        'mixed': TrafficPattern.MIXED,
    }
    
    # Add clients
    for config in client_configs:
        cid = config['cid']
        pattern_name = config.get('pattern', 'normal')
        pattern = pattern_map.get(pattern_name, TrafficPattern.NORMAL)
        seed = config.get('seed')
        
        simulator.add_client(
            cid=cid,
            pattern=pattern,
            seed=seed
        )
    
    # Run federation
    return simulator.run_federation(
        num_rounds=num_rounds,
        num_packets_per_round=num_packets,
        num_test_packets=num_test_packets
    )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    # Run a simple 2-client simulation
    print("Running 2-Client Federation Simulation...")
    
    results = run_simulation(
        client_configs=[
            {'cid': 'client_A', 'pattern': 'port_scan', 'seed': 42},
            {'cid': 'client_B', 'pattern': 'normal', 'seed': 123},
        ],
        num_rounds=3,
        num_packets=50,
        num_test_packets=30
    )
    
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    
    for round_info in results['round_history']:
        print(f"\nRound {round_info['round']}:")
        print(f"  Loss: {round_info['avg_loss']:.4f}")
        print(f"  Accuracy: {round_info['avg_accuracy']:.4f}")
    
    print("\n✓ Simulation complete!")

