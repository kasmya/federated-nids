#!/usr/bin/env python3
"""
Day 3: Dataset & Multi-Client Simulation - Complete Runner

Usage:
    # Generate datasets
    python run_day3.py --generate
    
    # Run Non-IID scenario (recommended)
    python run_day3.py run non_iid
    
    # Run IID scenario
    python run_day3.py run iid
    
    # Generate visualizations
    python run_day3.py visualize
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def generate_datasets():
    """Generate all datasets."""
    print("\n" + "="*60)
    print("STEP 1: GENERATING DATASETS")
    print("="*60)
    
    from federated.dataset_generator import generate_all_partitions, generate_iid_partitions
    
    print("\n--- Generating Non-IID partitions ---")
    non_iid = generate_all_partitions(packets_per_client=3000)
    
    print("\n--- Generating IID partitions ---")
    iid = generate_iid_partitions(packets_per_client=3000)
    
    print("\n✓ Datasets generated!")
    print(f"  Non-IID: {len(non_iid)} clients")
    print(f"  IID: {len(iid)} clients")


def run_scenario(scenario: str, rounds: int = 3):
    """Run a specific scenario."""
    print("\n" + "="*60)
    print(f"STEP 2: RUNNING {scenario.upper()} SCENARIO")
    print("="*60)
    
    from federated.orchestrator import run_non_iid_scenario, run_iid_scenario
    
    if scenario == 'iid':
        results = run_iid_scenario(num_rounds=rounds)
    else:
        results = run_non_iid_scenario(num_rounds=rounds)
    
    print("\n✓ Scenario complete!")
    return results


def visualize_results():
    """Generate visualizations."""
    print("\n" + "="*60)
    print("STEP 3: GENERATING VISUALIZATIONS")
    print("="*60)
    
    from federated.visualize import MetricsVisualizer
    
    visualizer = MetricsVisualizer()
    
    try:
        visualizer.load_results()
    except FileNotFoundError:
        print("No results found. Run a scenario first.")
        return
    
    plots = visualizer.generate_all_plots()
    report = visualizer.generate_summary_report()
    
    print("\n" + "="*60)
    print("VISUALIZATION COMPLETE")
    print("="*60)
    print(report)


def quick_test():
    """Quick test of all components."""
    print("\n" + "="*60)
    print("QUICK TEST - All Day 3 Components")
    print("="*60)
    
    # Test dataset generator
    print("\n--- Testing Dataset Generator ---")
    from federated.dataset_generator import generate_client_partition, get_partition_stats
    
    packets = generate_client_partition('test', 500, 'port_scan', 0.3)
    stats = get_partition_stats(packets)
    print(f"Generated {stats['total_packets']} packets")
    print(f"Attack %: {stats['attack_percent']:.1f}%")
    
    # Test packet replay
    print("\n--- Testing Packet Replay ---")
    from federated.packet_replay import PacketReplayEngine
    
    processed = []
    
    def callback(pkt):
        processed.append(pkt)
        return None
    
    engine = PacketReplayEngine(packets[:100], rate=50, callback=callback)
    engine.process_batch(50)
    print(f"Processed {len(processed)} packets")
    
    # Test enhanced client
    print("\n--- Testing Enhanced Client ---")
    import json
    import tempfile
    
    # Save temp data
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({'metadata': {'num_packets': len(packets)}, 'packets': packets[:100]}, f)
        temp_file = f.name
    
    from federated.enhanced_client import EnhancedFederatedClient
    
    client = EnhancedFederatedClient(
        cid='test_client',
        data_file=temp_file,
        consensus_server_url='http://localhost:5000',
        packets_per_round=50
    )
    
    # Process a round
    result = client.process_round_packets(0)
    print(f"Round packets: {result.get('packets_processed', 0)}")
    print(f"Anomalies: {result.get('anomalies_detected', 0)}")
    
    # Cleanup
    os.unlink(temp_file)
    
    print("\n" + "="*60)
    print("✓ ALL TESTS PASSED!")
    print("="*60)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Day 3: Dataset & Multi-Client')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    subparsers.add_parser('generate', help='Generate datasets')
    subparsers.add_parser('visualize', help='Generate visualizations')
    subparsers.add_parser('test', help='Quick test')
    
    run_parser = subparsers.add_parser('run', help='Run scenario')
    run_parser.add_argument('scenario', choices=['iid', 'non_iid'], default='non_iid')
    run_parser.add_argument('--rounds', type=int, default=3)
    
    args = parser.parse_args()
    
    if args.command == 'generate':
        generate_datasets()
    elif args.command == 'run':
        run_scenario(args.scenario, args.rounds)
    elif args.command == 'visualize':
        visualize_results()
    elif args.command == 'test':
        quick_test()
    else:
        # Default: run quick test + generate datasets + run scenario
        quick_test()
        generate_datasets()
        run_scenario('non_iid', rounds=3)


if __name__ == '__main__':
    main()

