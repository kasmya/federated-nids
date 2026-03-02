#!/usr/bin/env python3
"""
Federated NIDS - Day 3: Orchestrator Script
Runs 3-client federation with real packet data
"""

import os
import sys
import json
import time
import logging
import argparse
import subprocess
import signal
from datetime import datetime
from typing import Dict, Any, List, Optional
from multiprocessing import Process

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_CONFIG = {
    'num_rounds': 5,
    'packets_per_round': 500,
    'data_dir': 'federated/data',
    'output_dir': 'federated/results',
    'log_dir': 'federated/logs',
    'consensus_server': 'http://localhost:5000',
    'scenario': 'non_iid',  # or 'iid', 'zero_day'
}


# ============================================================================
# ORCHESTRATOR
# ============================================================================

class FederatedOrchestrator:
    """
    Orchestrates the federated learning run with multiple clients.
    
    Manages:
    - Data generation/loading
    - Client processes
    - Server (optional)
    - Metrics collection
    - Logging
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize orchestrator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        
        # Setup directories
        self.output_dir = self.config['output_dir']
        self.log_dir = self.config['log_dir']
        
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Client configs
        self.client_configs = []
        
        # Results storage
        self.run_results = {
            'config': self.config,
            'start_time': None,
            'end_time': None,
            'rounds': [],
            'client_metrics': {},
        }
        
        # Process tracking
        self.processes = []
        
        # Logger
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Setup logging to file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(self.log_dir, f'orchestrator_{timestamp}.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Logging to {log_file}")
    
    def prepare_data(self, scenario: str = None) -> Dict[str, str]:
        """
        Prepare data partitions for clients.
        
        Args:
            scenario: 'iid', 'non_iid', or 'zero_day'
            
        Returns:
            Dict mapping client_id to data file path
        """
        scenario = scenario or self.config['scenario']
        
        self.logger.info(f"Preparing data for scenario: {scenario}")
        
        # Generate partitions
        if scenario == 'iid':
            from federated.dataset_generator import generate_iid_partitions
            partitions = generate_iid_partitions(
                output_dir=self.config['data_dir'],
                packets_per_client=5000
            )
        else:
            from federated.dataset_generator import generate_all_partitions
            partitions = generate_all_partitions(
                output_dir=self.config['data_dir'],
                packets_per_client=5000
            )
        
        # Load and verify
        for client_id, filepath in partitions.items():
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Data file not found: {filepath}")
        
        self.logger.info(f"Data prepared: {len(partitions)} partitions")
        
        return partitions
    
    def setup_clients(self, data_partitions: Dict[str, str]) -> List[Dict]:
        """
        Setup client configurations.
        
        Args:
            data_partitions: Dict of client_id -> data file
            
        Returns:
            List of client configs
        """
        configs = []
        
        for client_id, data_file in data_partitions.items():
            # Determine attack focus based on client
            if 'client_A' in client_id:
                focus = 'port_scan'
            elif 'client_B' in client_id:
                focus = 'syn_flood'
            else:
                focus = 'mixed'
            
            config = {
                'cid': client_id,
                'data_file': data_file,
                'packets_per_round': self.config['packets_per_round'],
                'attack_focus': focus,
                'consensus_server': self.config['consensus_server'],
            }
            
            configs.append(config)
            self.logger.info(f"Client config: {client_id} - {focus}")
        
        self.client_configs = configs
        return configs
    
    def run_simulation(self) -> Dict[str, Any]:
        """
        Run the complete federated simulation.
        
        Returns:
            Results dictionary
        """
        self.logger.info("="*60)
        self.logger.info("STARTING FEDERATED SIMULATION")
        self.logger.info("="*60)
        
        self.run_results['start_time'] = datetime.now().isoformat()
        
        # Import components
        from federated.enhanced_client import EnhancedFederatedClient
        from federated.utils import aggregate_parameters_fedavg
        
        # Create clients
        self.logger.info("Creating clients...")
        clients = []
        
        for config in self.client_configs:
            client = EnhancedFederatedClient(
                cid=config['cid'],
                data_file=config['data_file'],
                consensus_server_url=config['consensus_server'],
                packets_per_round=config['packets_per_round']
            )
            clients.append(client)
            self.logger.info(f"  Created {config['cid']}")
        
        # Get initial parameters
        initial_params = clients[0].get_parameters()
        current_params = initial_params
        
        # Run federated rounds
        for round_num in range(1, self.config['num_rounds'] + 1):
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"ROUND {round_num}/{self.config['num_rounds']}")
            self.logger.info(f"{'='*60}")
            
            round_start = time.time()
            
            # Collect parameters from clients
            client_params = []
            client_results = []
            
            for client in clients:
                self.logger.info(f"Processing {client.cid}...")
                
                # Fit with data
                new_params, num_samples, metrics = client.fit_with_data(
                    current_params,
                    {'round_number': round_num}
                )
                
                client_params.append(new_params)
                client_results.append({
                    'cid': client.cid,
                    'samples': num_samples,
                    'metrics': metrics,
                })
                
                # Log client results
                self.logger.info(f"  {client.cid}: {metrics.get('packets_processed', 0)} packets, "
                               f"{metrics.get('anomalies_detected', 0)} anomalies, "
                               f"{metrics.get('rules_generated', 0)} rules")
            
            # Aggregate parameters (FedAvg)
            self.logger.info("Aggregating parameters...")
            current_params = aggregate_parameters_fedavg(client_params)
            
            # Log round results
            round_time = time.time() - round_start
            
            round_summary = {
                'round': round_num,
                'time_seconds': round_time,
                'clients': client_results,
            }
            
            # Calculate averages
            avg_packets = sum(r['metrics'].get('packets_processed', 0) for r in client_results)
            avg_anomalies = sum(r['metrics'].get('anomalies_detected', 0) for r in client_results)
            avg_rules = sum(r['metrics'].get('rules_generated', 0) for r in client_results)
            
            round_summary['averages'] = {
                'packets': avg_packets // len(clients),
                'anomalies': avg_anomalies,
                'rules': avg_rules,
            }
            
            self.run_results['rounds'].append(round_summary)
            
            self.logger.info(f"Round {round_num} complete in {round_time:.2f}s")
            self.logger.info(f"  Avg packets: {avg_packets // len(clients)}")
            self.logger.info(f"  Total anomalies: {avg_anomalies}")
            self.logger.info(f"  Total rules: {avg_rules}")
        
        # Save final results
        self.run_results['end_time'] = datetime.now().isoformat()
        
        # Collect final client metrics
        for client in clients:
            self.run_results['client_metrics'][client.cid] = {
                'total_packets': client.total_packets_processed,
                'rounds_participated': client.current_round,
                'round_metrics': client.round_metrics,
            }
            
            # Save client metrics
            client.save_metrics(
                os.path.join(self.output_dir, f'{client.cid}_metrics.json')
            )
        
        # Save overall results
        self._save_results()
        
        self.logger.info("="*60)
        self.logger.info("SIMULATION COMPLETE")
        self.logger.info("="*60)
        
        return self.run_results
    
    def _save_results(self) -> None:
        """Save run results to files."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save JSON
        json_file = os.path.join(self.output_dir, f'run_results_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump(self.run_results, f, indent=2)
        
        self.logger.info(f"Results saved to {json_file}")
        
        # Save CSV
        csv_file = os.path.join(self.output_dir, f'round_metrics_{timestamp}.csv')
        self._save_csv(csv_file)
        
        self.logger.info(f"CSV saved to {csv_file}")
    
    def _save_csv(self, filepath: str) -> None:
        """Save results as CSV."""
        import csv
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'round', 'client', 'packets_processed', 'anomalies_detected',
                'rules_generated', 'attack_packets', 'normal_packets',
                'global_rules', 'time_seconds'
            ])
            
            # Data
            for round_data in self.run_results.get('rounds', []):
                round_num = round_data.get('round', 0)
                round_time = round_data.get('time_seconds', 0)
                
                for client_data in round_data.get('clients', []):
                    metrics = client_data.get('metrics', {})
                    
                    writer.writerow([
                        round_num,
                        client_data.get('cid', ''),
                        metrics.get('packets_processed', 0),
                        metrics.get('anomalies_detected', 0),
                        metrics.get('rules_generated', 0),
                        metrics.get('attack_packets_seen', 0),
                        metrics.get('normal_packets_seen', 0),
                        metrics.get('global_rules_received', 0),
                        round_time
                    ])


# ============================================================================
# SCENARIO RUNNERS
# ============================================================================

def run_non_iid_scenario(num_rounds: int = 5) -> Dict:
    """Run Non-IID scenario (different attack patterns)."""
    print("\n" + "="*60)
    print("SCENARIO: NON-IID (Different Attack Patterns)")
    print("="*60)
    
    config = {
        'num_rounds': num_rounds,
        'packets_per_round': 500,
        'scenario': 'non_iid',
    }
    
    orchestrator = FederatedOrchestrator(config)
    
    # Prepare data
    partitions = orchestrator.prepare_data('non_iid')
    
    # Setup clients
    orchestrator.setup_clients(partitions)
    
    # Run
    results = orchestrator.run_simulation()
    
    return results


def run_iid_scenario(num_rounds: int = 5) -> Dict:
    """Run IID scenario (same attack distribution)."""
    print("\n" + "="*60)
    print("SCENARIO: IID (Same Attack Distribution)")
    print("="*60)
    
    config = {
        'num_rounds': num_rounds,
        'packets_per_round': 500,
        'scenario': 'iid',
    }
    
    orchestrator = FederatedOrchestrator(config)
    
    # Prepare data
    partitions = orchestrator.prepare_data('iid')
    
    # Setup clients
    orchestrator.setup_clients(partitions)
    
    # Run
    results = orchestrator.run_simulation()
    
    return results


def run_zero_day_scenario(num_rounds: int = 5) -> Dict:
    """Run Zero-Day scenario (new attack in round 5)."""
    print("\n" + "="*60)
    print("SCENARIO: ZERO-DAY ATTACK")
    print("="*60)
    print("Note: Zero-day requires special data - using non-iid for now")
    
    # For zero-day, we'd need to generate special data
    # For now, fall back to non-iid
    return run_non_iid_scenario(num_rounds)


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Run Federated NIDS Simulation')
    parser.add_argument('scenario', choices=['iid', 'non_iid', 'zero_day'], 
                       help='Scenario to run')
    parser.add_argument('--rounds', type=int, default=5, help='Number of rounds')
    parser.add_argument('--packets', type=int, default=500, help='Packets per round')
    
    args = parser.parse_args()
    
    print(f"\n{'#'*60}")
    print(f"# FEDERATED NIDS - DAY 3 SIMULATION")
    print(f"# Scenario: {args.scenario}")
    print(f"# Rounds: {args.rounds}")
    print(f"# Packets/round: {args.packets}")
    print(f"{'#'*60}\n")
    
    # Run appropriate scenario
    if args.scenario == 'iid':
        results = run_iid_scenario(args.rounds)
    elif args.scenario == 'zero_day':
        results = run_zero_day_scenario(args.rounds)
    else:
        results = run_non_iid_scenario(args.rounds)
    
    # Print summary
    print("\n" + "="*60)
    print("SIMULATION SUMMARY")
    print("="*60)
    
    total_time = 0
    total_packets = 0
    total_anomalies = 0
    total_rules = 0
    
    for round_data in results.get('rounds', []):
        total_time += round_data.get('time_seconds', 0)
        for client in round_data.get('clients', []):
            metrics = client.get('metrics', {})
            total_packets += metrics.get('packets_processed', 0)
            total_anomalies += metrics.get('anomalies_detected', 0)
            total_rules += metrics.get('rules_generated', 0)
    
    print(f"Total time: {total_time:.2f}s")
    print(f"Total packets: {total_packets}")
    print(f"Total anomalies: {total_anomalies}")
    print(f"Total rules: {total_rules}")
    print(f"Rounds: {len(results.get('rounds', []))}")
    
    print("\n✓ Simulation complete!")
    print(f"Results saved to: federated/results/")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

