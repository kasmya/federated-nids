#!/usr/bin/env python3
"""
Federated NIDS - Day 3: Metrics Visualization
Generates graphs from collected metrics for paper
"""

import os
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional
import subprocess

# Try to import matplotlib, provide fallback if not available
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not available, will save data only")


class MetricsVisualizer:
    """
    Generates visualizations from federated NIDS metrics.
    
    Creates:
    - Detection rate over rounds
    - Rule generation over time
    - Consensus latency
    - Communication cost comparison
    """
    
    def __init__(self, results_dir: str = "federated/results"):
        """
        Initialize visualizer.
        
        Args:
            results_dir: Directory containing results
        """
        self.results_dir = results_dir
        self.results = None
        self.output_dir = os.path.join(results_dir, "visualizations")
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def load_results(self, filepath: str = None) -> Dict:
        """Load results from file."""
        if filepath is None:
            # Find latest results
            files = [f for f in os.listdir(self.results_dir) 
                    if f.startswith('run_results_') and f.endswith('.json')]
            
            if not files:
                raise FileNotFoundError("No results found")
            
            filepath = os.path.join(self.results_dir, sorted(files)[-1])
        
        with open(filepath, 'r') as f:
            self.results = json.load(f)
        
        print(f"Loaded results from {filepath}")
        return self.results
    
    def plot_detection_rate(self) -> Optional[str]:
        """Plot detection rate over rounds."""
        if not HAS_MATPLOTLIB:
            return None
        
        rounds = []
        client_data = {}
        
        for round_info in self.results.get('rounds', []):
            round_num = round_info.get('round', 0)
            rounds.append(round_num)
            
            for client in round_info.get('clients', []):
                cid = client.get('cid', 'unknown')
                metrics = client.get('metrics', {})
                
                packets = metrics.get('packets_processed', 1)
                anomalies = metrics.get('anomalies_detected', 0)
                attacks = metrics.get('attack_packets_seen', 1)
                
                # Detection rate = anomalies / attack packets
                rate = anomalies / max(1, attacks)
                
                if cid not in client_data:
                    client_data[cid] = []
                client_data[cid].append(rate * 100)  # Convert to percentage
        
        # Plot
        fig, ax = plt.subplots(figsize=(10, 6))
        
        for cid, data in client_data.items():
            ax.plot(rounds[:len(data)], data, marker='o', label=cid, linewidth=2)
        
        ax.set_xlabel('Federated Round', fontsize=12)
        ax.set_ylabel('Detection Rate (%)', fontsize=12)
        ax.set_title('Anomaly Detection Rate Over Rounds', fontsize=14)
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 100)
        
        output_file = os.path.join(self.output_dir, 'detection_rate.png')
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"Saved: {output_file}")
        return output_file
    
    def plot_rule_generation(self) -> Optional[str]:
        """Plot rule generation over rounds."""
        if not HAS_MATPLOTLIB:
            return None
        
        rounds = []
        client_data = {}
        total_rules = []
        
        for round_info in self.results.get('rounds', []):
            round_num = round_info.get('round', 0)
            rounds.append(round_num)
            
            round_total = 0
            for client in round_info.get('clients', []):
                cid = client.get('cid', 'unknown')
                rules = client.get('metrics', {}).get('rules_generated', 0)
                
                if cid not in client_data:
                    client_data[cid] = []
                client_data[cid].append(rules)
                
                round_total += rules
            
            total_rules.append(round_total)
        
        # Plot
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Per-client
        for cid, data in client_data.items():
            ax1.plot(rounds[:len(data)], data, marker='s', label=cid, linewidth=2)
        
        ax1.set_xlabel('Federated Round', fontsize=12)
        ax1.set_ylabel('Rules Generated', fontsize=12)
        ax1.set_title('Rule Generation Per Client', fontsize=14)
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Total
        ax2.bar(rounds, total_rules, color='steelblue', alpha=0.7)
        ax2.set_xlabel('Federated Round', fontsize=12)
        ax2.set_ylabel('Total Rules', fontsize=12)
        ax2.set_title('Total Rules Generated', fontsize=14)
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        output_file = os.path.join(self.output_dir, 'rule_generation.png')
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"Saved: {output_file}")
        return output_file
    
    def plot_communication_cost(self) -> Optional[str]:
        """Plot communication cost (simulated)."""
        if not HAS_MATPLOTLIB:
            return None
        
        rounds = []
        upload_cost = []
        download_cost = []
        
        # Simulated costs based on data
        # Upload: parameters + rules
        # Download: aggregated parameters + global rules
        
        for round_info in self.results.get('rounds', []):
            round_num = round_info.get('round', 0)
            rounds.append(round_num)
            
            # Estimate: ~10KB per parameter set, ~1KB per rule
            num_clients = len(round_info.get('clients', []))
            params_size = num_clients * 10  # KB
            
            rules_count = sum(
                c.get('metrics', {}).get('rules_generated', 0)
                for c in round_info.get('clients', [])
            )
            rules_size = rules_count * 1  # KB
            
            upload_cost.append(params_size + rules_size)
            download_cost.append(10 + rules_count * 0.5)  # KB
        
        # Plot
        fig, ax = plt.subplots(figsize=(10, 6))
        
        x = list(range(len(rounds)))
        width = 0.35
        
        ax.bar([i - width/2 for i in x], upload_cost, width, label='Upload', color='coral')
        ax.bar([i + width/2 for i in x], download_cost, width, label='Download', color='steelblue')
        
        ax.set_xlabel('Federated Round', fontsize=12)
        ax.set_ylabel('Communication (KB)', fontsize=12)
        ax.set_title('Communication Cost Per Round', fontsize=14)
        ax.set_xticks(x)
        ax.set_xticklabels(rounds)
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        output_file = os.path.join(self.output_dir, 'communication_cost.png')
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"Saved: {output_file}")
        return output_file
    
    def plot_round_time(self) -> Optional[str]:
        """Plot round execution time."""
        if not HAS_MATPLOTLIB:
            return None
        
        rounds = []
        times = []
        
        for round_info in self.results.get('rounds', []):
            rounds.append(round_info.get('round', 0))
            times.append(round_info.get('time_seconds', 0))
        
        # Plot
        fig, ax = plt.subplots(figsize=(10, 6))
        
        ax.bar(rounds, times, color='forestgreen', alpha=0.7)
        ax.plot(rounds, times, marker='o', color='darkgreen', linewidth=2)
        
        ax.set_xlabel('Federated Round', fontsize=12)
        ax.set_ylabel('Time (seconds)', fontsize=12)
        ax.set_title('Round Execution Time', fontsize=14)
        ax.grid(True, alpha=0.3)
        
        # Add average line
        avg_time = sum(times) / len(times) if times else 0
        ax.axhline(y=avg_time, color='red', linestyle='--', label=f'Avg: {avg_time:.2f}s')
        ax.legend()
        
        output_file = os.path.join(self.output_dir, 'round_time.png')
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"Saved: {output_file}")
        return output_file
    
    def generate_all_plots(self) -> List[str]:
        """Generate all plots."""
        if not HAS_MATPLOTLIB:
            print("Matplotlib not available, skipping visualizations")
            return []
        
        print("\nGenerating visualizations...")
        
        plots = []
        
        plots.append(self.plot_detection_rate())
        plots.append(self.plot_rule_generation())
        plots.append(self.plot_communication_cost())
        plots.append(self.plot_round_time())
        
        return [p for p in plots if p is not None]
    
    def generate_summary_report(self) -> str:
        """Generate text summary report."""
        report = []
        
        report.append("="*60)
        report.append("FEDERATED NIDS SIMULATION RESULTS")
        report.append("="*60)
        report.append("")
        
        # Config
        config = self.results.get('config', {})
        report.append("Configuration:")
        report.append(f"  Scenario: {config.get('scenario', 'unknown')}")
        report.append(f"  Rounds: {config.get('num_rounds', 0)}")
        report.append(f"  Packets/round: {config.get('packets_per_round', 0)}")
        report.append("")
        
        # Timing
        start = self.results.get('start_time', '')
        end = self.results.get('end_time', '')
        report.append(f"Start: {start}")
        report.append(f"End: {end}")
        report.append("")
        
        # Totals
        total_packets = 0
        total_anomalies = 0
        total_rules = 0
        
        for round_info in self.results.get('rounds', []):
            for client in round_info.get('clients', []):
                metrics = client.get('metrics', {})
                total_packets += metrics.get('packets_processed', 0)
                total_anomalies += metrics.get('anomalies_detected', 0)
                total_rules += metrics.get('rules_generated', 0)
        
        report.append("Totals:")
        report.append(f"  Packets processed: {total_packets}")
        report.append(f"  Anomalies detected: {total_anomalies}")
        report.append(f"  Rules generated: {total_rules}")
        report.append("")
        
        # Per-round summary
        report.append("Per-Round Summary:")
        for round_info in self.results.get('rounds', []):
            r = round_info.get('round', 0)
            t = round_info.get('time_seconds', 0)
            avgs = round_info.get('averages', {})
            
            report.append(f"  Round {r}: {t:.2f}s, "
                        f"avg packets: {avgs.get('packets', 0)}, "
                        f"total anomalies: {avgs.get('anomalies', 0)}")
        
        report.append("")
        report.append("="*60)
        
        report_text = "\n".join(report)
        
        # Save report
        report_file = os.path.join(self.output_dir, 'summary_report.txt')
        with open(report_file, 'w') as f:
            f.write(report_text)
        
        print(f"Saved: {report_file}")
        
        return report_text


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Visualize federated NIDS results')
    parser.add_argument('--results', type=str, default=None,
                       help='Path to results JSON file')
    parser.add_argument('--dir', type=str, default='federated/results',
                       help='Results directory')
    
    args = parser.parse_args()
    
    print("="*60)
    print("FEDERATED NIDS METRICS VISUALIZATION")
    print("="*60)
    
    # Create visualizer
    if args.results:
        visualizer = MetricsVisualizer(os.path.dirname(args.results))
        visualizer.load_results(args.results)
    else:
        visualizer = MetricsVisualizer(args.dir)
        visualizer.load_results()
    
    # Generate plots
    plots = visualizer.generate_all_plots()
    
    # Generate report
    report = visualizer.generate_summary_report()
    
    print("\n" + "="*60)
    print("VISUALIZATION COMPLETE")
    print("="*60)
    print(f"\nGenerated {len(plots)} plots")
    print(f"Output directory: {visualizer.output_dir}")
    print("\nSummary Report:")
    print(report)


if __name__ == '__main__':
    main()

