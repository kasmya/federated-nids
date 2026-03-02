# Day 1: Foundation & Flower Setup - TODO List

## Phase 1: Environment Setup
- [x] 1.1 Update requirements.txt with Flower and dependencies
- [x] 1.2 Create federated/ directory structure
- [x] 1.3 Create verification script to confirm Flower installation

## Phase 2: Minimal Client Wrapper
- [x] 2.1 Create federated/__init__.py
- [x] 2.2 Create federated/utils.py with parameter serialization helpers
- [x] 2.3 Create federated/client.py with MinimalFederatedClient class

## Phase 3: Minimal Server
- [x] 3.1 Create federated/server.py with FedAvg aggregation
- [x] 3.2 Configure for 2-3 clients
- [x] 3.3 Add logging and statistics tracking

## Phase 4: Client Simulator
- [x] 4.1 Create federated/simulation.py with packet generator
- [x] 4.2 Implement different traffic patterns (port scan vs normal)
- [x] 4.3 Integrate with ClosedLoopNIDS class

## Phase 5: Testing & Integration
- [x] 5.1 Create federated/test_federation.py script
- [x] 5.2 Verify client-server communication
- [x] 5.3 Monitor parameter exchange
- [x] 5.4 Add optional Flask dashboard integration

## Completion Criteria
- [x] All clients can connect to server
- [x] Parameters are exchanged successfully
- [x] FedAvg aggregation works
- [x] Federation rounds complete without errors

## Files Created

| File | Description |
|------|-------------|
| `federated/__init__.py` | Package exports |
| `federated/utils.py` | Serialization & FedAvg |
| `federated/client.py` | MinimalFederatedClient (500+ lines) |
| `federated/server.py` | FederatedServer |
| `federated/simulation.py` | Traffic/Client simulators |
| `federated/test_federation.py` | Test suite |
| `federated/verify_install.py` | Verification script |
| `federated/dashboard_integration.py` | Flask API endpoints |
| `federated/README.md` | Documentation |
| `run_federation.py` | Quick runner script |
| `DAY1_TODO.md` | Task tracking |

## How to Run

```bash
# Install dependencies
pip install flwr numpy

# Quick test
python run_federation.py --test

# Full simulation
python run_federation.py --rounds 3 --clients 2 --packets 100

# Or use the runner
python run_federation.py
```

