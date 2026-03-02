#!/usr/bin/env python3
"""
Federated NIDS - Verification Script
Day 1: Foundation & Flower Setup

Verifies that all dependencies are correctly installed.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def check_python_version():
    """Check Python version."""
    print("="*60)
    print("Checking Python version...")
    
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("⚠ Warning: Python 3.8+ recommended")
        return False
    
    print("✓ Python version OK")
    return True


def check_dependencies():
    """Check required dependencies."""
    print("\n" + "="*60)
    print("Checking dependencies...")
    
    dependencies = [
        ('flwr', 'Flower'),
        ('numpy', 'NumPy'),
        ('flask', 'Flask'),
        ('flask_socketio', 'Flask-SocketIO'),
    ]
    
    all_ok = True
    
    for module_name, display_name in dependencies:
        try:
            module = __import__(module_name)
            version = getattr(module, '__version__', 'unknown')
            print(f"✓ {display_name}: {version}")
        except ImportError:
            print(f"✗ {display_name}: NOT INSTALLED")
            all_ok = False
    
    return all_ok


def check_closed_loop():
    """Check ClosedLoopNIDS package."""
    print("\n" + "="*60)
    print("Checking ClosedLoopNIDS package...")
    
    try:
        from closed_loop import ClosedLoopNIDS
        print("✓ ClosedLoopNIDS imported successfully")
        
        # Try creating an instance
        nids = ClosedLoopNIDS()
        print(f"✓ ClosedLoopNIDS created")
        print(f"  - Detection threshold: {nids.detector.detection_threshold}")
        print(f"  - Window size: {nids.detector.window_size}")
        
        return True
    except Exception as e:
        print(f"✗ ClosedLoopNIDS error: {e}")
        return False


def check_federated_package():
    """Check Federated NIDS package."""
    print("\n" + "="*60)
    print("Checking Federated NIDS package...")
    
    try:
        from federated import (
            MinimalFederatedClient,
            FederatedServer,
            PacketSimulator,
            run_simulation,
        )
        print("✓ Federated package imported successfully")
        print("  - MinimalFederatedClient")
        print("  - FederatedServer")
        print("  - PacketSimulator")
        print("  - run_simulation")
        
        return True
    except Exception as e:
        print(f"✗ Federated package error: {e}")
        return False


def check_client_functionality():
    """Check client can be created."""
    print("\n" + "="*60)
    print("Checking client functionality...")
    
    try:
        from federated.client import MinimalFederatedClient
        
        # Create client without simulation
        client = MinimalFederatedClient(
            cid='verify_client',
            traffic_pattern='normal',
            simulate_traffic=False
        )
        
        print(f"✓ Client created: {client.cid}")
        
        # Get parameters
        params = client.get_parameters()
        print(f"✓ get_parameters() returned {len(params)} arrays")
        
        # Test set_parameters
        client.set_parameters(params)
        print(f"✓ set_parameters() completed")
        
        return True
    except Exception as e:
        print(f"✗ Client functionality error: {e}")
        return False


def check_simulation():
    """Check simulation works."""
    print("\n" + "="*60)
    print("Checking simulation...")
    
    try:
        from federated.simulation import run_simulation
        
        # Run a small simulation
        results = run_simulation(
            client_configs=[
                {'cid': 'client_A', 'pattern': 'normal', 'seed': 42},
                {'cid': 'client_B', 'pattern': 'normal', 'seed': 123},
            ],
            num_rounds=1,
            num_packets=10,
            num_test_packets=5
        )
        
        print(f"✓ Simulation completed: {results['status']}")
        
        return True
    except Exception as e:
        print(f"✗ Simulation error: {e}")
        return False


def main():
    """Run all verification checks."""
    print("\n" + "="*60)
    print("FEDERATED NIDS - VERIFICATION SCRIPT")
    print("Day 1: Foundation & Flower Setup")
    print("="*60)
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("ClosedLoopNIDS", check_closed_loop),
        ("Federated Package", check_federated_package),
        ("Client Functionality", check_client_functionality),
        ("Simulation", check_simulation),
    ]
    
    results = []
    
    for check_name, check_func in checks:
        try:
            success = check_func()
            results.append((check_name, success))
        except Exception as e:
            print(f"✗ {check_name} crashed: {e}")
            results.append((check_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("VERIFICATION SUMMARY")
    print("="*60)
    
    passed = 0
    failed = 0
    
    for check_name, success in results:
        symbol = "✓" if success else "✗"
        print(f"{symbol} {check_name}")
        
        if success:
            passed += 1
        else:
            failed += 1
    
    print(f"\nTotal: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n" + "="*60)
        print("ALL CHECKS PASSED!")
        print("="*60)
        print("\nYou can now run the federated learning system:")
        print("  python federated/test_federation.py --mode simulation")
        print("\nOr start the server:")
        print("  python federated/server.py")
        return 0
    else:
        print("\n⚠ Some checks failed. Please install missing dependencies:")
        print("  pip install -r requirements.txt")
        return 1


if __name__ == '__main__':
    sys.exit(main())

