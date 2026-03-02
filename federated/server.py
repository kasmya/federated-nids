#!/usr/bin/env python3
"""
Federated NIDS - Minimal Server
Day 1: Foundation & Flower Setup

This module provides:
- FederatedServer: Flower server with FedAvg aggregation
- Configuration for multiple clients
- Logging and statistics tracking
"""

import numpy as np
import logging
import os
import sys
import time
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Flower imports - use new API for Flower 1.x
import flwr
from flwr.server import server as flower_server
from flwr.server.strategy import FedAvg
from flwr.common import (
    Parameters, 
    Scalar, 
    parameters_to_ndarrays,
    ndarrays_to_parameters,
)

logger = logging.getLogger(__name__)

# ============================================================================
# FEDERATED SERVER
# ============================================================================

class FederatedServer:
    """
    Federated Learning Server for NIDS.
    
    This server coordinates federated learning across multiple NIDS clients
    using the FedAvg aggregation strategy.
    
    Features:
    - FedAvg aggregation
    - Configurable number of rounds
    - Client selection
    - Statistics tracking and logging
    - Integration with Flower framework
    
    Usage:
        server = FederatedServer(num_rounds=5, num_clients=2)
        server.run()
    """
    
    def __init__(
        self,
        num_rounds: int = 3,
        num_clients: int = 2,
        fraction_fit: float = 1.0,
        fraction_evaluate: float = 1.0,
        min_fit_clients: int = 2,
        min_evaluate_clients: int = 2,
        min_available_clients: int = 2,
        server_address: str = "[::]:8080",
        log_dir: str = "federated/logs"
    ):
        """
        Initialize the federated server.
        
        Args:
            num_rounds: Number of federation rounds
            num_clients: Expected number of clients
            fraction_fit: Fraction of clients to use for training
            fraction_evaluate: Fraction of clients to use for evaluation
            min_fit_clients: Minimum clients for training
            min_evaluate_clients: Minimum clients for evaluation
            min_available_clients: Minimum available clients to start
            server_address: Server address to bind to
            log_dir: Directory for logs
        """
        self.num_rounds = num_rounds
        self.num_clients = num_clients
        self.fraction_fit = fraction_fit
        self.fraction_evaluate = fraction_evaluate
        self.min_fit_clients = min_fit_clients
        self.min_evaluate_clients = min_evaluate_clients
        self.min_available_clients = min_available_clients
        self.server_address = server_address
        self.log_dir = log_dir
        
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        
        # Statistics
        self.stats = {
            'current_round': 0,
            'rounds_completed': 0,
            'total_clients_connected': 0,
            'total_fit_operations': 0,
            'total_evaluate_operations': 0,
            'round_history': [],
            'start_time': None,
            'end_time': None,
        }
        
        # Server state
        self.current_weights = None
        self.is_running = False
        
        # Initialize Flower server components
        self._init_flower_server()
        
        print(f"\n{'='*60}")
        print("Federated NIDS Server Initialized")
        print(f"{'='*60}")
        print(f"Rounds: {num_rounds}")
        print(f"Expected Clients: {num_clients}")
        print(f"Server Address: {server_address}")
        print(f"Min Available Clients: {min_available_clients}")
        print(f"{'='*60}\n")
    
    def _init_flower_server(self):
        """Initialize the Flower server with FedAvg strategy."""
        
        # Create FedAvg strategy
        self.strategy = FedAvg(
            fraction_fit=self.fraction_fit,
            fraction_evaluate=self.fraction_evaluate,
            min_fit_clients=self.min_fit_clients,
            min_evaluate_clients=self.min_evaluate_clients,
            min_available_clients=self.min_available_clients,
            # Aggregation function
            fit_metrics_aggregation_fn=self._aggregate_fit_metrics,
            evaluate_metrics_aggregation_fn=self._aggregate_evaluate_metrics,
        )
        
        # Initialize server
        self.flwr_server = flower_server.Server(
            client_manager=None,  # Will be set when running
            strategy=self.strategy,
        )
    
    def _aggregate_fit_metrics(self, metrics: List[Tuple[int, Dict]]) -> Dict[str, Scalar]:
        """
        Aggregate metrics from fit operations.
        
        Args:
            metrics: List of (cid, metrics_dict) tuples
            
        Returns:
            Aggregated metrics
        """
        if not metrics:
            return {}
        
        # Calculate weighted averages
        total_samples = sum(num_samples for num_samples, _ in metrics)
        
        aggregated = {
            'fit_loss': 0.0,
            'anomalies_detected': 0.0,
            'rules_generated': 0.0,
            'packets_processed': 0.0,
            'fit_time': 0.0,
        }
        
        for num_samples, m in metrics:
            weight = num_samples / total_samples if total_samples > 0 else 0
            
            aggregated['fit_loss'] += weight * m.get('loss', 0)
            aggregated['anomalies_detected'] += m.get('anomalies_detected', 0)
            aggregated['rules_generated'] += m.get('rules_generated', 0)
            aggregated['packets_processed'] += m.get('packets_processed', 0)
            aggregated['fit_time'] += m.get('fit_time', 0)
        
        print(f"\n[Server] Aggregated fit metrics:")
        print(f"  - Loss: {aggregated['fit_loss']:.4f}")
        print(f"  - Anomalies detected: {aggregated['anomalies_detected']:.0f}")
        print(f"  - Rules generated: {aggregated['rules_generated']:.0f}")
        print(f"  - Packets processed: {aggregated['packets_processed']:.0f}")
        
        return aggregated
    
    def _aggregate_evaluate_metrics(self, metrics: List[Tuple[int, Dict]]) -> Dict[str, Scalar]:
        """
        Aggregate metrics from evaluate operations.
        
        Args:
            metrics: List of (cid, metrics_dict) tuples
            
        Returns:
            Aggregated metrics
        """
        if not metrics:
            return {}
        
        # Simple averaging
        num_clients = len(metrics)
        
        aggregated = {
            'loss': 0.0,
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
        }
        
        for _, m in metrics:
            aggregated['loss'] += m.get('loss', 0) / num_clients
            aggregated['accuracy'] += m.get('accuracy', 0) / num_clients
            aggregated['precision'] += m.get('precision', 0) / num_clients
            aggregated['recall'] += m.get('recall', 0) / num_clients
        
        print(f"\n[Server] Aggregated evaluate metrics:")
        print(f"  - Loss: {aggregated['loss']:.4f}")
        print(f"  - Accuracy: {aggregated['accuracy']:.4f}")
        print(f"  - Precision: {aggregated['precision']:.4f}")
        print(f"  - Recall: {aggregated['recall']:.4f}")
        
        return aggregated
    
    def run(self) -> None:
        """
        Start the federated server.
        
        This runs the Flower server which will:
        1. Wait for clients to connect
        2. Start federation rounds
        3. Aggregate parameters using FedAvg
        4. Repeat for num_rounds
        """
        print("\n" + "="*60)
        print("Starting Federated NIDS Server")
        print("="*60 + "\n")
        
        self.stats['start_time'] = datetime.now().isoformat()
        self.is_running = True
        
        # Start Flower server
        # The server will block until stopped
        try:
            flwr.server.start_server(
                server_address=self.server_address,
                server=self.flwr_server,
                config={"num_rounds": self.num_rounds},
            )
        except KeyboardInterrupt:
            print("\n[Server] Shutting down...")
        finally:
            self.is_running = False
            self.stats['end_time'] = datetime.now().isoformat()
            self._save_stats()
    
    def run_simulation(
        self, 
        clients: List[Any],
        num_rounds: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Run a simulation with provided clients (without actual Flower network).
        
        This is useful for testing without network setup.
        
        Args:
            clients: List of MinimalFederatedClient instances
            num_rounds: Number of rounds (default: self.num_rounds)
            
        Returns:
            Final results
        """
        if num_rounds is None:
            num_rounds = self.num_rounds
        
        print("\n" + "="*60)
        print("Running Federated Simulation")
        print(f"Clients: {[c.cid for c in clients]}")
        print(f"Rounds: {num_rounds}")
        print("="*60 + "\n")
        
        self.stats['start_time'] = datetime.now().isoformat()
        
        # Initial parameters (from first client)
        current_params = clients[0].get_parameters()
        print(f"[Server] Initial parameters from {clients[0].cid}: {len(current_params)} arrays")
        
        # Log initial parameters
        for i, arr in enumerate(current_params):
            print(f"  Array {i}: shape={arr.shape}, mean={arr.mean():.4f}")
        
        for round_num in range(1, num_rounds + 1):
            print(f"\n{'='*60}")
            print(f"FEDERATION ROUND {round_num}/{num_rounds}")
            print(f"{'='*60}")
            
            self.stats['current_round'] = round_num
            
            # Collect parameters from all clients
            client_params = []
            client_results = []
            
            for client in clients:
                print(f"\n[Server] Getting parameters from {client.cid}...")
                
                # Client fit (local training)
                new_params, num_samples, metrics = client.fit(
                    current_params,
                    {'round_number': round_num, 'num_packets': 50}
                )
                
                client_params.append(new_params)
                client_results.append({
                    'cid': client.cid,
                    'num_samples': num_samples,
                    'metrics': metrics
                })
                
                print(f"[Server] {client.cid}: {num_samples} samples, metrics={metrics}")
            
            # Aggregate using FedAvg
            print(f"\n[Server] Aggregating {len(client_params)} client parameters...")
            from federated.utils import aggregate_parameters_fedavg
            
            current_params = aggregate_parameters_fedavg(client_params)
            
            # Log aggregated parameters
            print(f"[Server] Aggregated parameters:")
            for i, arr in enumerate(current_params):
                print(f"  Array {i}: shape={arr.shape}, mean={arr.mean():.4f}, std={arr.std():.4f}")
            
            # Update round stats
            round_stats = {
                'round': round_num,
                'clients': [c.cid for c in clients],
                'client_results': client_results,
                'timestamp': datetime.now().isoformat(),
            }
            self.stats['round_history'].append(round_stats)
            
            # Evaluate with all clients
            print(f"\n[Server] Running evaluation...")
            eval_results = []
            for client in clients:
                loss, num_samples, eval_metrics = client.evaluate(
                    current_params,
                    {'round_number': round_num, 'num_test_packets': 30}
                )
                eval_results.append({
                    'cid': client.cid,
                    'loss': loss,
                    'metrics': eval_metrics
                })
            
            # Log evaluation results
            avg_loss = sum(r['loss'] for r in eval_results) / len(eval_results)
            avg_accuracy = sum(r['metrics'].get('accuracy', 0) for r in eval_results) / len(eval_results)
            
            print(f"\n[Server] Round {round_num} Evaluation:")
            print(f"  Average Loss: {avg_loss:.4f}")
            print(f"  Average Accuracy: {avg_accuracy:.4f}")
            
            self.stats['total_fit_operations'] += len(clients)
            self.stats['total_evaluate_operations'] += len(clients)
            self.stats['rounds_completed'] = round_num
            
            # Save checkpoint
            self._save_checkpoint(round_num, current_params)
        
        self.stats['end_time'] = datetime.now().isoformat()
        
        # Save final stats
        self._save_stats()
        
        print("\n" + "="*60)
        print("FEDERATED SIMULATION COMPLETE")
        print("="*60)
        print(f"Total rounds: {self.stats['rounds_completed']}")
        print(f"Total fit operations: {self.stats['total_fit_operations']}")
        
        return {
            'status': 'complete',
            'num_rounds': self.stats['rounds_completed'],
            'stats': self.stats,
            'final_parameters': current_params,
        }
    
    def _save_checkpoint(self, round_num: int, parameters: List[np.ndarray]) -> None:
        """Save a checkpoint of the current parameters."""
        checkpoint_dir = os.path.join(self.log_dir, "checkpoints")
        os.makedirs(checkpoint_dir, exist_ok=True)
        
        checkpoint_file = os.path.join(checkpoint_dir, f"round_{round_num}.npz")
        
        # Save arrays
        arrays_dict = {f'param_{i}': arr for i, arr in enumerate(parameters)}
        np.savez(checkpoint_file, **arrays_dict)
        
        print(f"[Server] Saved checkpoint: {checkpoint_file}")
    
    def _save_stats(self) -> None:
        """Save server statistics to file."""
        stats_file = os.path.join(self.log_dir, "server_stats.json")
        
        # Convert numpy types to Python types for JSON
        stats_json = self._convert_stats_for_json(self.stats)
        
        with open(stats_file, 'w') as f:
            json.dump(stats_json, f, indent=2)
        
        print(f"[Server] Saved statistics: {stats_file}")
    
    def _convert_stats_for_json(self, stats: Dict) -> Dict:
        """Convert stats dictionary for JSON serialization."""
        result = {}
        for key, value in stats.items():
            if isinstance(value, np.ndarray):
                result[key] = value.tolist()
            elif isinstance(value, (np.integer, np.floating)):
                result[key] = int(value) if isinstance(value, np.integer) else float(value)
            elif isinstance(value, list):
                result[key] = [
                    self._convert_stats_for_json(item) if isinstance(item, dict) else item
                    for item in value
                ]
            elif isinstance(value, dict):
                result[key] = self._convert_stats_for_json(value)
            else:
                result[key] = value
        return result
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get server status.
        
        Returns:
            Status dictionary
        """
        return {
            'is_running': self.is_running,
            'num_rounds': self.num_rounds,
            'current_round': self.stats['current_round'],
            'rounds_completed': self.stats['rounds_completed'],
            'stats': self.stats,
        }


# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

def create_federated_server(
    num_rounds: int = 3,
    num_clients: int = 2,
    server_address: str = "[::]:8080",
    log_dir: str = "federated/logs"
) -> FederatedServer:
    """
    Factory function to create a federated server.
    
    Args:
        num_rounds: Number of federation rounds
        num_clients: Number of expected clients
        server_address: Server address
        log_dir: Log directory
        
    Returns:
        FederatedServer instance
    """
    return FederatedServer(
        num_rounds=num_rounds,
        num_clients=num_clients,
        server_address=server_address,
        log_dir=log_dir
    )


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Run a simple simulation
    print("Starting Federated NIDS Server Simulation...")
    
    # Create server
    server = FederatedServer(
        num_rounds=3,
        num_clients=2,
        log_dir="federated/logs"
    )
    
    # Import clients
    from federated.client import MinimalFederatedClient
    
    # Create clients with different traffic patterns
    client_a = MinimalFederatedClient(
        cid='client_A',
        traffic_pattern='port_scan',
        simulate_traffic=True
    )
    
    client_b = MinimalFederatedClient(
        cid='client_B',
        traffic_pattern='normal',
        simulate_traffic=True
    )
    
    # Run simulation
    results = server.run_simulation(
        clients=[client_a, client_b],
        num_rounds=3
    )
    
    print("\n" + "="*60)
    print("SIMULATION RESULTS")
    print("="*60)
    print(json.dumps(results['stats'], indent=2))
    
    print("\n✓ Federated server test complete!")

