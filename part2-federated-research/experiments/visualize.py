#!/usr/bin/env python3
"""
Visualize Experiment Results
Generates graphs from experiment results for the paper
"""

import os
import json
import sys
from datetime import datetime
from typing import Dict, List

# Try to import matplotlib
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def load_results(results_dir: str = "results") -> List[Dict]:
    """Load all experiment result files"""
    results = []
    
    if not os.path.exists(results_dir):
        print(f"Results directory '{results_dir}' not found")
        return results
    
    for f in os.listdir(results_dir):
        if f.endswith(".json"):
            with open(os.path.join(results_dir, f)) as fp:
                data = json.load(fp)
                results.append({'filename': f, 'data': data})
    
    return results


def visualize_results():
    """Generate visualizations from results"""
    print("="*50)
    print("VISUALIZATION")
    print("="*50)
    
    if not HAS_MATPLOTLIB:
        print("matplotlib not installed. Install with: pip install matplotlib")
        return
    
    results = load_results()
    
    if not results:
        print("No results found. Run experiments first: python -m experiments.run")
        return
    
    print(f"Found {len(results)} result files")
    
    # Create output directory
    output_dir = "results/visualizations"
    os.makedirs(output_dir, exist_ok=True)
    
    # Example: Plot rule generation per round
    for result in results:
        data = result['data']
        
        # Extract metrics
        scenarios = {}
        for scenario, scenario_data in data.items():
            rounds = []
            rules_per_round = []
            
            for round_data in scenario_data.get('rounds', []):
                round_num = round_data.get('round', 0)
                total_rules = 0
                
                for client in round_data.get('clients', []):
                    total_rules += client.get('metrics', {}).get('rules_generated', 0)
                
                rounds.append(round_num)
                rules_per_round.append(total_rules)
            
            scenarios[scenario] = {'rounds': rounds, 'rules': rules_per_round}
        
        # Create plot
        plt.figure(figsize=(10, 6))
        
        for scenario, metrics in scenarios.items():
            plt.plot(metrics['rounds'], metrics['rules'], 
                    marker='o', label=scenario.upper())
        
        plt.xlabel('Federated Round')
        plt.ylabel('Total Rules Generated')
        plt.title('Rule Generation Across Federated Rounds')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Save
        output_file = os.path.join(output_dir, 
                                  f"rules_{result['filename'].replace('.json', '.png')}")
        plt.savefig(output_file)
        plt.close()
        
        print(f"✓ Saved: {output_file}")
    
    # Generate summary report
    generate_summary_report(data, output_dir)
    
    print(f"\n✓ Visualizations complete!")


def generate_summary_report(data: Dict, output_dir: str):
    """Generate text summary report"""
    report = []
    report.append("="*60)
    report.append("EXPERIMENT SUMMARY REPORT")
    report.append("="*60)
    report.append("")
    
    for scenario, scenario_data in data.items():
        report.append(f"Scenario: {scenario.upper()}")
        report.append("-" * 40)
        
        # Global rules
        global_rules = scenario_data.get('final_global_rules', [])
        report.append(f"Global rules created: {len(global_rules)}")
        
        for rule in global_rules:
            report.append(f"  ★ {rule.get('rule_string', '')[:60]}...")
            report.append(f"    Supported by: {rule.get('supporting_clients', [])}")
        
        # Round breakdown
        report.append("")
        report.append("Round breakdown:")
        for round_data in scenario_data.get('rounds', []):
            round_num = round_data.get('round', 0)
            report.append(f"  Round {round_num}:")
            
            for client in round_data.get('clients', []):
                cid = client.get('cid', '')
                metrics = client.get('metrics', {})
                report.append(f"    {cid}: {metrics.get('rules_generated', 0)} rules, "
                            f"{metrics.get('anomalies_detected', 0)} anomalies")
        
        report.append("")
    
    report_text = "\n".join(report)
    
    # Save report
    report_file = os.path.join(output_dir, "summary_report.txt")
    with open(report_file, "w") as f:
        f.write(report_text)
    
    print(f"✓ Saved: {report_file}")
    print("\n" + report_text)


def main():
    visualize_results()


if __name__ == "__main__":
    main()

