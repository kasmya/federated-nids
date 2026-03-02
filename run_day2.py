#!/usr/bin/env python3
"""
Federated NIDS - Day 2: Complete Runner
Runs the complete consensus workflow with 3 clients
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_day2():
    """Run Day 2 consensus test."""
    print("\n" + "="*70)
    print("DAY 2: RULE CONSENSUS ENGINE - COMPLETE TEST")
    print("="*70)
    
    # Run consensus test
    from federated.test_consensus import test_consensus_engine, test_consensus_with_simulation
    
    print("\n--- Part 1: Direct Consensus Engine Test ---")
    test_consensus_engine()
    
    print("\n--- Part 2: Full Simulation Test ---")
    test_consensus_with_simulation()
    
    print("\n" + "="*70)
    print("DAY 2 COMPLETE!")
    print("="*70)
    print("""
To run with Flask server:
1. Start Flask: python app.py
2. In another terminal: python federated/test_consensus.py --flask

To run full consensus simulation:
python federated/test_consensus.py --simulate
""")


if __name__ == '__main__':
    run_day2()

