#!/usr/bin/env python3
"""
Experiment Runner - Run all scenarios and collect results
Usage: python -m experiments.run
"""

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from federation import FederatedClient, FederatedServer


def run_experiment(scenario: str, num_rounds: int = 3) -> dict:
    """Run a single experiment scenario"""
    
    print(f"\n{'#'*60}")
    print(f"# EXPERIMENT: {scenario.upper()}")
    print(f"# Rounds: {num_rounds}")
    print(f"{'#'*60}")
    
    # Define clients based on scenario
    if scenario == "iid":
        clients = [
            FederatedClient("client_A", "port_scan"),
            FederatedClient("client_B", "syn_flood"),
            FederatedClient("client_C", "port_scan"),  # Same as A
        ]
    elif scenario == "non_iid":
        clients = [
            FederatedClient("client_A", "port_scan"),
            FederatedClient("client_B", "syn_flood"),
            FederatedClient("client_C", "mixed"),
        ]
    else:  # zero_day
        clients = [
            FederatedClient("client_A", "port_scan"),
            FederatedClient("client_B", "normal"),
            FederatedClient("client_C", "normal"),
        ]
    
    # Run simulation
    server = FederatedServer(num_rounds=num_rounds)
    results = server.run_simulation(clients)
    
    # Add metadata
    results['scenario'] = scenario
    results['timestamp'] = datetime.now().isoformat()
    
    return results


def main():
    """Run all scenarios"""
    scenarios = ["non_iid", "iid"]  # Add "zero_day" if desired
    
    all_results = {}
    
    for scenario in scenarios:
        results = run_experiment(scenario, num_rounds=3)
        all_results[scenario] = results
    
    # Save results
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    with open(f"results/experiment_{timestamp}.json", "w") as f:
        json.dump(all_results, f, indent=2)
    
    # Print summary
    print(f"\n{'='*60}")
    print("EXPERIMENT SUMMARY")
    print(f"{'='*60}")
    
    for scenario, results in all_results.items():
        print(f"\n{scenario.upper()}:")
        print(f"  Global rules created: {len(results.get('final_global_rules', []))}")
        for round_data in results.get('rounds', []):
            for cr in round_data.get('clients', []):
                print(f"  Round {round_data['round']}: {cr['cid']} - "
                      f"{cr['metrics']['rules_generated']} rules")
    
    print(f"\n✓ Results saved to results/experiment_{timestamp}.json")


if __name__ == "__main__":
    main()
