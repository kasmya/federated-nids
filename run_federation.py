#!/usr/bin/env python3
"""
Federated NIDS - Day 1 Runner Script
Quick script to run the federation system

Usage:
    python run_federation.py              # Run 2-client simulation
    python run_federation.py --rounds 5   # Run 5 rounds
    python run_federation.py --clients 3   # Run with 3 clients
"""

import argparse
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    parser = argparse.ArgumentParser(description="Run Federated NIDS")
    parser.add_argument('--rounds', type=int, default=3, help='Number of federation rounds')
    parser.add_argument('--clients', type=int, default=2, help='Number of clients')
    parser.add_argument('--packets', type=int, default=100, help='Packets per round')
    parser.add_argument('--test', action='store_true', help='Run test mode (1 round, 2 clients)')
    
    args = parser.parse_args()
    
    from federated.simulation import run_simulation
    
    # Configure based on args
    if args.test:
        num_rounds = 1
        num_clients = 2
        num_packets = 30
    else:
        num_rounds = args.rounds
        num_clients = args.clients
        num_packets = args.packets
    
    # Define client configurations
    patterns = ['port_scan', 'normal', 'syn_flood', 'ddos', 'brute_force']
    
    client_configs = []
    for i in range(num_clients):
        client_configs.append({
            'cid': f'client_{chr(65 + i)}',  # client_A, client_B, etc.
            'pattern': patterns[i % len(patterns)],
            'seed': 42 + i
        })
    
    print("="*60)
    print("FEDERATED NIDS - DAY 1")
    print("="*60)
    print(f"Rounds: {num_rounds}")
    print(f"Clients: {num_clients}")
    print(f"Packets per round: {num_packets}")
    print("="*60)
    print()
    
    # Run simulation
    results = run_simulation(
        client_configs=client_configs,
        num_rounds=num_rounds,
        num_packets=num_packets,
        num_test_packets=50
    )
    
    # Print summary
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    print(f"Status: {results['status']}")
    print(f"Rounds completed: {results['num_rounds']}")
    print(f"Clients: {results['num_clients']}")
    
    print("\nRound-by-round:")
    for round_info in results['round_history']:
        print(f"  Round {round_info['round']}: Loss={round_info['avg_loss']:.4f}, Accuracy={round_info['avg_accuracy']:.4f}")
    
    print("\n" + "="*60)
    print("✓ Day 1 Federation Complete!")
    print("="*60)


if __name__ == '__main__':
    main()

