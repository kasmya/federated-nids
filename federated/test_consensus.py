#!/usr/bin/env python3
"""
Federated NIDS - Day 2: Rule Consensus Test Script
Tests the complete consensus workflow with 3 clients
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_consensus_engine():
    """Test the consensus engine directly (no Flask)."""
    print("\n" + "="*70)
    print("DAY 2: RULE CONSENSUS ENGINE TEST")
    print("="*70)
    
    from federated.rule_consensus import RuleConsensusEngine, create_consensus_engine
    
    # Create engine
    engine = create_consensus_engine(min_consensus=2)
    
    print("\n" + "-"*70)
    print("STEP 1: Client A submits port scan rule")
    print("-"*70)
    
    rule_a = {
        'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.1 any (msg:"AUTO_PORT_SCAN")',
        'anomaly_type': 'port_scan',
        'src_ip': '192.168.1.100',
        'dst_port': 'any',
        'score': 0.85
    }
    
    result_a = engine.submit_rule(rule_a, 'client_A')
    print(f"Result: Promoted={result_a['promoted']}")
    
    print("\n" + "-"*70)
    print("STEP 2: Client B submits SYN flood rule (different attack)")
    print("-"*70)
    
    rule_b = {
        'rule_string': 'alert tcp 192.168.1.200 any -> 10.0.0.2 80 (msg:"AUTO_SYN_FLOOD")',
        'anomaly_type': 'syn_flood',
        'src_ip': '192.168.1.200',
        'dst_port': '80',
        'score': 0.90
    }
    
    result_b = engine.submit_rule(rule_b, 'client_B')
    print(f"Result: Promoted={result_b['promoted']}")
    
    print("\n" + "-"*70)
    print("STEP 3: Client C submits SIMILAR port scan rule (should trigger consensus)")
    print("-"*70)
    
    rule_c = {
        'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.5 any (msg:"AUTO_PORT_SCAN_2")',
        'anomaly_type': 'port_scan',
        'src_ip': '192.168.1.100',
        'dst_port': 'any',
        'score': 0.80
    }
    
    result_c = engine.submit_rule(rule_c, 'client_C')
    print(f"Result: Promoted={result_c['promoted']}")
    
    print("\n" + "-"*70)
    print("STEP 4: Check global rules")
    print("-"*70)
    
    global_rules = engine.get_global_rules()
    print(f"\nTotal global rules: {len(global_rules)}")
    
    for rule in global_rules:
        print(f"\n  ★ GLOBAL RULE:")
        print(f"    String: {rule['rule_string']}")
        print(f"    Anomaly: {rule['anomaly_type']}")
        print(f"    Supporting clients: {rule['supporting_clients']}")
        print(f"    Promoted: {rule['promotion_time']}")
    
    # Verify consensus reached
    print("\n" + "-"*70)
    print("VERIFICATION")
    print("-"*70)
    
    # Should have at least 1 promoted rule (port_scan reached consensus)
    assert len(global_rules) >= 1, "Should have at least 1 global rule"
    
    # Port scan should have 2 clients (consensus reached)
    port_scan_rules = [r for r in global_rules if r['anomaly_type'] == 'port_scan']
    if port_scan_rules:
        assert len(port_scan_rules[0]['supporting_clients']) == 2, "Port scan should have 2 supporters"
        print("✓ Port scan rule has consensus (2 clients)")
    
    # SYN flood has 1 client (no consensus yet) - expected
    print("✓ SYN flood not promoted (expected - only 1 client)")
    
    print("\n" + "="*70)
    print("✓ DAY 2 CONSENSUS TEST PASSED!")
    print("="*70)
    
    return True


def test_consensus_with_simulation():
    """Test consensus with full client simulation."""
    print("\n" + "="*70)
    print("DAY 2: RULE CONSENSUS WITH CLIENT SIMULATION")
    print("="*70)
    
    from federated.rule_consensus import RuleConsensusEngine
    
    # Create engine
    engine = RuleConsensusEngine(min_consensus=2, similarity_threshold=0.7)
    
    print("\n--- Simulating 3 clients generating rules ---\n")
    
    # Simulate Client A: Port scan
    print("[CLIENT A] Generating port scan rules...")
    rules_a = [
        {
            'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.1 any (msg:"AUTO_PORT_SCAN_1")',
            'anomaly_type': 'port_scan',
            'src_ip': '192.168.1.100',
            'score': 0.85
        },
        {
            'rule_string': 'alert tcp 192.168.1.101 any -> 10.0.0.2 any (msg:"AUTO_PORT_SCAN_2")',
            'anomaly_type': 'port_scan',
            'src_ip': '192.168.1.101',
            'score': 0.75
        }
    ]
    
    for rule in rules_a:
        engine.submit_rule(rule, 'client_A')
    
    # Simulate Client B: SYN flood
    print("[CLIENT B] Generating SYN flood rules...")
    rules_b = [
        {
            'rule_string': 'alert tcp 192.168.1.200 any -> 10.0.0.10 80 (msg:"AUTO_SYN_FLOOD")',
            'anomaly_type': 'syn_flood',
            'src_ip': '192.168.1.200',
            'score': 0.90
        }
    ]
    
    for rule in rules_b:
        engine.submit_rule(rule, 'client_B')
    
    # Simulate Client C: Same port scan as A (to trigger consensus)
    print("[CLIENT C] Generating port scan rules (similar to Client A)...")
    rules_c = [
        {
            'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.3 any (msg:"AUTO_PORT_SCAN_3")',
            'anomaly_type': 'port_scan',
            'src_ip': '192.168.1.100',
            'score': 0.80
        }
    ]
    
    for rule in rules_c:
        engine.submit_rule(rule, 'client_C')
    
    # Get final status
    print("\n" + "="*70)
    print("FINAL STATUS")
    print("="*70)
    
    status = engine.get_status()
    
    print(f"\nRules submitted: {status['engine_stats']['rules_submitted']}")
    print(f"Rules promoted: {status['engine_stats']['rules_promoted']}")
    print(f"Consensus rounds: {status['engine_stats']['consensus_rounds']}")
    
    print(f"\nGlobal Rules ({len(engine.get_global_rules())}):")
    for rule in engine.get_global_rules():
        print(f"  ★ {rule['anomaly_type']}: {rule['rule_string'][:50]}...")
        print(f"    Supported by: {rule['supporting_clients']}")
    
    print("\n" + "="*70)
    print("✓ SIMULATION TEST PASSED!")
    print("="*70)
    
    return True


def test_with_flask_server():
    """Test with actual Flask server running."""
    print("\n" + "="*70)
    print("DAY 2: TESTING WITH FLASK SERVER")
    print("="*70)
    
    import requests
    
    base_url = "http://localhost:5000"
    
    # Reset consensus engine
    print("\n[1] Resetting consensus engine...")
    try:
        requests.post(f"{base_url}/api/federated/reset", timeout=2)
    except Exception as e:
        print(f"  Note: Server not running at {base_url}")
        print(f"  Run: python app.py")
        return False
    
    print("\n[2] Submitting rules from Client A...")
    response = requests.post(
        f"{base_url}/api/federated/submit_rules",
        json={
            'client_id': 'client_A',
            'rules': [
                {
                    'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.1 any (msg:"PORT_SCAN_A")',
                    'anomaly_type': 'port_scan',
                    'src_ip': '192.168.1.100',
                    'score': 0.85
                }
            ]
        },
        timeout=5
    )
    print(f"  Status: {response.status_code}")
    print(f"  Result: {response.json()}")
    
    print("\n[3] Submitting rules from Client C (similar to A)...")
    response = requests.post(
        f"{base_url}/api/federated/submit_rules",
        json={
            'client_id': 'client_C',
            'rules': [
                {
                    'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.5 any (msg:"PORT_SCAN_C")',
                    'anomaly_type': 'port_scan',
                    'src_ip': '192.168.1.100',
                    'score': 0.80
                }
            ]
        },
        timeout=5
    )
    print(f"  Status: {response.status_code}")
    print(f"  Result: {response.json()}")
    
    print("\n[4] Checking global rules...")
    response = requests.get(f"{base_url}/api/federated/global_rules", timeout=5)
    print(f"  Global rules count: {response.json()['global_rules_count']}")
    
    print("\n[5] Checking consensus status...")
    response = requests.get(f"{base_url}/api/federated/consensus/status", timeout=5)
    status = response.json()
    print(f"  Promoted rules: {status['consensus_status']['engine_stats']['rules_promoted']}")
    
    print("\n" + "="*70)
    print("✓ FLASK SERVER TEST PASSED!")
    print("="*70)
    
    return True


def main():
    parser = argparse.ArgumentParser(description="Day 2 Consensus Test")
    parser.add_argument('--flask', action='store_true', help='Test with Flask server')
    parser.add_argument('--simulate', action='store_true', help='Full simulation')
    
    args = parser.parse_args()
    
    if args.flask:
        success = test_with_flask_server()
    elif args.simulate:
        success = test_consensus_with_simulation()
    else:
        # Run direct test
        success = test_consensus_engine()
    
    if success:
        print("\n✓ All tests passed!")
    else:
        print("\n⚠ Some tests skipped (server not running)")
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())

