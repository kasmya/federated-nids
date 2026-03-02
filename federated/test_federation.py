#!/usr/bin/env python3
"""
Federated NIDS - Testing Script
Day 1: Foundation & Flower Setup

This script tests the federated learning system:
- Verifies clients can communicate
- Monitors parameter exchange
- Logs federation rounds

Usage:
    # Test simulation mode (no network required):
    python federated/test_federation.py --mode simulation
    
    # Test with Flower server (requires network):
    python federated/test_federation.py --mode server
"""

import argparse
import json
import os
import sys
import time
import logging
from typing import Dict, Any, List

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_parameter_serialization():
    """Test parameter serialization/deserialization."""
    print("\n" + "="*60)
    print("TEST 1: Parameter Serialization")
    print("="*60)
    
    from federated.utils import serialize_parameters, deserialize_parameters
    
    # Test parameters
    test_params = {
        'detection_threshold': 0.5,
        'baseline_stats': {
            'packet_rate': {'value': 5.0, 'std': 3.0},
            'port_diversity': {'value': 3.0, 'std': 2.0},
            'connection_rate': {'value': 2.0, 'std': 2.0},
            'bytes_per_second': {'value': 1000.0, 'std': 500.0},
            'dns_query_rate': {'value': 0.5, 'std': 0.5},
            'icmp_count': {'value': 1.0, 'std': 1.0},
        },
        'adaptation_rate': 0.1,
    }
    
    # Serialize
    arrays = serialize_parameters(test_params)
    print(f"✓ Serialized to {len(arrays)} arrays")
    
    for i, arr in enumerate(arrays):
        print(f"  Array {i}: shape={arr.shape}, values={arr}")
    
    # Deserialize
    recovered = deserialize_parameters(arrays)
    print(f"✓ Deserialized parameters")
    
    # Verify
    assert test_params['detection_threshold'] == recovered['detection_threshold'], "Threshold mismatch"
    assert test_params['baseline_stats']['packet_rate']['value'] == recovered['baseline_stats']['packet_rate']['value'], "Baseline mismatch"
    
    print("\n✓ TEST 1 PASSED: Parameter serialization works!")
    return True


def test_fedavg_aggregation():
    """Test FedAvg aggregation."""
    print("\n" + "="*60)
    print("TEST 2: FedAvg Aggregation")
    print("="*60)
    
    import numpy as np
    from federated.utils import aggregate_parameters_fedavg
    
    # Create mock parameters from 3 clients
    client1_params = [
        np.array([0.5], dtype=np.float32),  # threshold
        np.array([5.0, 3.0], dtype=np.float32),  # packet_rate
        np.array([3.0, 2.0], dtype=np.float32),  # port_diversity
    ]
    
    client2_params = [
        np.array([0.6], dtype=np.float32),
        np.array([6.0, 4.0], dtype=np.float32),
        np.array([4.0, 3.0], dtype=np.float32),
    ]
    
    client3_params = [
        np.array([0.4], dtype=np.float32),
        np.array([4.0, 2.0], dtype=np.float32),
        np.array([2.0, 1.0], dtype=np.float32),
    ]
    
    parameters = [client1_params, client2_params, client3_params]
    
    # Aggregate
    aggregated = aggregate_parameters_fedavg(parameters)
    
    print(f"✓ Aggregated {len(parameters)} parameter sets into {len(aggregated)} arrays")
    
    # Verify (should be weighted average)
    expected_threshold = (0.5 + 0.6 + 0.4) / 3  # 0.5
    expected_pr_mean = (5.0 + 6.0 + 4.0) / 3  # 5.0
    
    print(f"  Threshold: {aggregated[0][0]:.4f} (expected: {expected_threshold:.4f})")
    print(f"  Packet rate mean: {aggregated[1][0]:.4f} (expected: {expected_pr_mean:.4f})")
    
    assert abs(aggregated[0][0] - expected_threshold) < 0.01, "Threshold aggregation failed"
    assert abs(aggregated[1][0] - expected_pr_mean) < 0.01, "PR mean aggregation failed"
    
    print("\n✓ TEST 2 PASSED: FedAvg aggregation works!")
    return True


def test_client_creation():
    """Test client creation."""
    print("\n" + "="*60)
    print("TEST 3: Client Creation")
    print("="*60)
    
    from federated.client import MinimalFederatedClient
    
    # Create client
    client = MinimalFederatedClient(
        cid='test_client',
        traffic_pattern='normal',
        simulate_traffic=False
    )
    
    print(f"✓ Created client: {client.cid}")
    print(f"  NIDS initialized: {client.nids is not None}")
    print(f"  Detection threshold: {client.nids.detector.detection_threshold}")
    
    assert client.cid == 'test_client', "Client ID mismatch"
    assert client.nids is not None, "NIDS not initialized"
    
    print("\n✓ TEST 3 PASSED: Client creation works!")
    return True


def test_client_fit_evaluate():
    """Test client fit and evaluate."""
    print("\n" + "="*60)
    print("TEST 4: Client Fit and Evaluate")
    print("="*60)
    
    from federated.client import MinimalFederatedClient
    
    # Create client with simulated traffic
    client = MinimalFederatedClient(
        cid='test_client',
        traffic_pattern='port_scan',
        simulate_traffic=True
    )
    
    # Get initial parameters
    params = client.get_parameters()
    print(f"✓ Got {len(params)} parameters")
    
    # Run fit
    new_params, num_samples, metrics = client.fit(
        params,
        {'round_number': 1, 'num_packets': 30}
    )
    
    print(f"✓ Fit completed:")
    print(f"  Samples: {num_samples}")
    print(f"  Anomalies: {metrics.get('anomalies_detected', 0)}")
    print(f"  Rules: {metrics.get('rules_generated', 0)}")
    
    # Run evaluate
    loss, num_test, eval_metrics = client.evaluate(
        new_params,
        {'round_number': 1, 'num_test_packets': 20}
    )
    
    print(f"✓ Evaluate completed:")
    print(f"  Loss: {loss:.4f}")
    print(f"  Accuracy: {eval_metrics.get('accuracy', 0):.4f}")
    
    assert num_samples > 0, "No samples processed"
    assert new_params is not None, "No parameters returned"
    
    print("\n✓ TEST 4 PASSED: Client fit and evaluate work!")
    return True


def test_two_client_simulation():
    """Test simulation with 2 clients."""
    print("\n" + "="*60)
    print("TEST 5: 2-Client Federation Simulation")
    print("="*60)
    
    from federated.server import FederatedServer
    from federated.client import MinimalFederatedClient
    
    # Create server
    server = FederatedServer(
        num_rounds=2,
        num_clients=2,
        log_dir="federated/test_logs"
    )
    
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
    
    print(f"✓ Created 2 clients: client_A (port_scan), client_B (normal)")
    
    # Run simulation
    results = server.run_simulation(
        clients=[client_a, client_b],
        num_rounds=2
    )
    
    print(f"✓ Simulation completed:")
    print(f"  Status: {results['status']}")
    print(f"  Rounds: {results['num_rounds']}")
    print(f"  Total fit operations: {results['stats']['total_fit_operations']}")
    
    assert results['status'] == 'complete', "Simulation failed"
    assert results['num_rounds'] == 2, "Wrong number of rounds"
    
    print("\n✓ TEST 5 PASSED: 2-client simulation works!")
    return True


def test_multi_client_simulation():
    """Test with 3 clients."""
    print("\n" + "="*60)
    print("TEST 6: 3-Client Federation Simulation")
    print("="*60)
    
    from federated.simulation import run_simulation
    
    # Run simulation
    results = run_simulation(
        client_configs=[
            {'cid': 'client_A', 'pattern': 'port_scan', 'seed': 42},
            {'cid': 'client_B', 'pattern': 'normal', 'seed': 123},
            {'cid': 'client_C', 'pattern': 'syn_flood', 'seed': 456},
        ],
        num_rounds=2,
        num_packets=30,
        num_test_packets=20
    )
    
    print(f"✓ Simulation completed:")
    print(f"  Status: {results['status']}")
    print(f"  Rounds: {results['num_rounds']}")
    print(f"  Clients: {results['num_clients']}")
    
    # Check round history
    for round_info in results['round_history']:
        print(f"\n  Round {round_info['round']}:")
        print(f"    Loss: {round_info['avg_loss']:.4f}")
        print(f"    Accuracy: {round_info['avg_accuracy']:.4f}")
    
    assert results['status'] == 'complete', "Simulation failed"
    assert results['num_clients'] == 3, "Wrong number of clients"
    
    print("\n✓ TEST 6 PASSED: 3-client simulation works!")
    return True


def test_integration():
    """Test integration with ClosedLoopNIDS."""
    print("\n" + "="*60)
    print("TEST 7: Integration with ClosedLoopNIDS")
    print("="*60)
    
    from closed_loop import ClosedLoopNIDS
    from federated.client import MinimalFederatedClient
    
    # Create standalone NIDS
    standalone_nids = ClosedLoopNIDS({
        'detection_threshold': 0.5,
        'auto_generate_rules': True
    })
    
    # Process some packets
    packets = [
        {'src': '192.168.1.100', 'dst': '10.0.0.1', 'proto': 'tcp', 
         'sport': 5000, 'dport': 80, 'flags': 'S', 'length': 64},
        {'src': '192.168.1.101', 'dst': '10.0.0.2', 'proto': 'tcp', 
         'sport': 5001, 'dport': 443, 'flags': 'PA', 'length': 500},
    ]
    
    for packet in packets * 10:
        standalone_nids.process_packet(packet)
    
    print(f"✓ Processed {20} packets")
    
    # Get rules
    rules = standalone_nids.rule_generator.get_all_rules()
    print(f"✓ Generated {len(rules)} rules")
    
    # Create federated client
    fed_client = MinimalFederatedClient(
        cid='integration_test',
        traffic_pattern='mixed',
        simulate_traffic=True
    )
    
    # Verify both use the same underlying components
    assert fed_client.nids.detector is not None, "Detector not initialized"
    assert fed_client.nids.rule_generator is not None, "Rule generator not initialized"
    
    print(f"✓ Federated client uses ClosedLoopNIDS: {type(fed_client.nids).__name__}")
    
    print("\n✓ TEST 7 PASSED: Integration works!")
    return True


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

def run_all_tests():
    """Run all tests."""
    print("\n" + "="*60)
    print("FEDERATED NIDS - COMPREHENSIVE TEST SUITE")
    print("Day 1: Foundation & Flower Setup")
    print("="*60)
    
    tests = [
        ("Parameter Serialization", test_parameter_serialization),
        ("FedAvg Aggregation", test_fedavg_aggregation),
        ("Client Creation", test_client_creation),
        ("Client Fit/Evaluate", test_client_fit_evaluate),
        ("2-Client Simulation", test_two_client_simulation),
        ("3-Client Simulation", test_multi_client_simulation),
        ("Integration", test_integration),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, "PASSED", None))
        except Exception as e:
            print(f"\n✗ TEST FAILED: {test_name}")
            print(f"  Error: {e}")
            results.append((test_name, "FAILED", str(e)))
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = 0
    failed = 0
    
    for test_name, status, error in results:
        symbol = "✓" if status == "PASSED" else "✗"
        print(f"{symbol} {test_name}: {status}")
        if error:
            print(f"  Error: {error}")
        
        if status == "PASSED":
            passed += 1
        else:
            failed += 1
    
    print(f"\nTotal: {passed} passed, {failed} failed")
    
    return failed == 0


def run_quick_test():
    """Run a quick test to verify basic functionality."""
    print("\nRunning quick verification test...")
    
    # Quick serialization test
    from federated.utils import serialize_parameters, deserialize_parameters
    import numpy as np
    
    params = {
        'detection_threshold': 0.5,
        'baseline_stats': {
            'packet_rate': {'value': 5.0, 'std': 3.0},
            'port_diversity': {'value': 3.0, 'std': 2.0},
            'connection_rate': {'value': 2.0, 'std': 2.0},
            'bytes_per_second': {'value': 1000.0, 'std': 500.0},
            'dns_query_rate': {'value': 0.5, 'std': 0.5},
            'icmp_count': {'value': 1.0, 'std': 1.0},
        },
        'adaptation_rate': 0.1,
    }
    
    arrays = serialize_parameters(params)
    recovered = deserialize_parameters(arrays)
    
    print(f"✓ Serialization: {len(arrays)} arrays")
    print(f"✓ Deserialization: threshold={recovered['detection_threshold']}")
    
    # Quick client test
    from federated.client import MinimalFederatedClient
    
    client = MinimalFederatedClient(
        cid='quick_test',
        traffic_pattern='normal',
        simulate_traffic=False
    )
    
    params = client.get_parameters()
    print(f"✓ Client: {len(params)} parameters")
    
    print("\n✓ Quick verification passed!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Federated NIDS Testing")
    parser.add_argument(
        '--mode',
        choices=['quick', 'simulation', 'server', 'all'],
        default='quick',
        help='Test mode'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.mode == 'quick':
        run_quick_test()
    elif args.mode == 'simulation':
        run_all_tests()
    elif args.mode == 'server':
        print("Server mode requires Flower to be installed and network setup.")
        print("Run: pip install flwr")
        print("Then start the server: python federated/server.py")
    elif args.mode == 'all':
        run_all_tests()


if __name__ == '__main__':
    main()

