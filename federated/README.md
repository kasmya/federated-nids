# Federated NIDS - Day 1: Foundation & Flower Setup

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- Flower (`flwr`) - Federated Learning framework
- NumPy - For parameter serialization
- All existing NIDS dependencies

### 2. Verify Installation

```bash
python federated/verify_install.py
```

Expected output:
```
============================================================
FEDERATED NIDS - VERIFICATION SCRIPT
============================================================
✓ Python version OK
✓ Flower: 1.x.x
✓ NumPy: 1.x.x
✓ ClosedLoopNIDS imported successfully
✓ Federated package imported successfully
✓ Client created: verify_client
✓ Simulation completed

ALL CHECKS PASSED!
```

### 3. Run Quick Test

```bash
python federated/test_federation.py --mode quick
```

### 4. Run Full Test Suite

```bash
python federated/test_federation.py --mode simulation
```

---

## Project Structure

```
nids-closed-loop/
├── federated/
│   ├── __init__.py           # Package exports
│   ├── utils.py              # Parameter serialization, FedAvg
│   ├── client.py              # MinimalFederatedClient class
│   ├── server.py              # FederatedServer with FedAvg
│   ├── simulation.py          # Packet/Client simulators
│   ├── test_federation.py    # Testing script
│   ├── verify_install.py     # Verification script
│   ├── dashboard_integration.py  # Flask API endpoints
│   └── README.md              # This file
│
├── closed_loop/               # Existing NIDS components
│   ├── anomaly_detector.py   # SimpleAnomalyDetector
│   ├── baselines.py          # AdaptiveBaseline
│   └── rule_generator.py    # RuleGenerator
│
└── requirements.txt          # Updated with flwr, numpy
```

---

## Components

### 1. MinimalFederatedClient

Wrapper for your ClosedLoopNIDS that participates in federated learning.

**Key Features:**
- Extracts parameters: detection_threshold, baseline means/stds
- Serializes to NumPy arrays for Flower
- Implements Flower interface: `get_parameters()`, `fit()`, `evaluate()`
- Generates and stores rules locally
- Simulated traffic generation

**Usage:**
```python
from federated.client import MinimalFederatedClient

# Create client with port scan pattern
client = MinimalFederatedClient(
    cid='client_A',
    traffic_pattern='port_scan',
    simulate_traffic=True
)

# Get parameters for federation
params = client.get_parameters()

# Run local training (fit)
new_params, num_samples, metrics = client.fit(
    params,
    {'round_number': 1, 'num_packets': 50}
)

# Evaluate
loss, num_samples, eval_metrics = client.evaluate(
    new_params,
    {'round_number': 1, 'num_test_packets': 30}
)
```

### 2. FederatedServer

Flower server with FedAvg aggregation.

**Usage (Simulation Mode):**
```python
from federated.server import FederatedServer
from federated.client import MinimalFederatedClient

# Create server
server = FederatedServer(
    num_rounds=3,
    num_clients=2,
    log_dir="federated/logs"
)

# Create clients
client_a = MinimalFederatedClient(cid='client_A', traffic_pattern='port_scan')
client_b = MinimalFederatedClient(cid='client_B', traffic_pattern='normal')

# Run simulation
results = server.run_simulation(
    clients=[client_a, client_b],
    num_rounds=3
)
```

### 3. PacketSimulator

Generates simulated network packets for testing.

**Traffic Patterns:**
- `normal` - Normal web traffic
- `port_scan` - Port scanning attack
- `syn_flood` - SYN flood attack
- `ddos` - DDoS attack
- `brute_force` - SSH brute force
- `mixed` - 80% normal, 20% attack

**Usage:**
```python
from federated.simulation import run_simulation

results = run_simulation(
    client_configs=[
        {'cid': 'client_A', 'pattern': 'port_scan'},
        {'cid': 'client_B', 'pattern': 'normal'},
    ],
    num_rounds=3,
    num_packets=100,
    num_test_packets=50
)
```

---

## Federated Parameters

The following NIDS parameters are federated:

| Parameter | Description |
|-----------|-------------|
| `detection_threshold` | Threshold for anomaly detection |
| `packet_rate` baseline | Mean and std for packet rate |
| `port_diversity` baseline | Mean and std for port diversity |
| `connection_rate` baseline | Mean and std for connection rate |
| `bytes_per_second` baseline | Mean and std for bandwidth |
| `dns_query_rate` baseline | Mean and std for DNS queries |
| `icmp_count` baseline | Mean and std for ICMP |
| `adaptation_rate` | How fast baselines adapt |

---

## Integration with Flask Dashboard (Optional)

### Add API Endpoints to app.py

```python
# Add to your imports
from federated.dashboard_integration import register_with_flask_app

# Register endpoints
register_with_flask_app(app, url_prefix='/api/federated')
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/federated/status` | GET | Get federation status |
| `/api/federated/clients` | GET | Get client status |
| `/api/federated/logs` | GET | Get federation logs |
| `/api/federated/start` | POST | Start federation |
| `/api/federated/stop` | POST | Stop federation |
| `/api/federated/results` | GET | Get results |

### Start Federation via API

```bash
curl -X POST http://localhost:5000/api/federated/start \
  -H "Content-Type: application/json" \
  -d '{
    "num_rounds": 3,
    "num_packets": 100,
    "client_configs": [
      {"cid": "client_A", "pattern": "port_scan"},
      {"cid": "client_B", "pattern": "normal"}
    ]
  }'
```

---

## Running with Flower Network (Advanced)

For actual network-based federated learning (not simulation):

### Start Server

```bash
python -m federated.server
```

### Start Clients (in separate terminals)

```bash
# Terminal 1: Client A
python -c "
from federated.client import MinimalFederatedClient
client = MinimalFederatedClient(cid='client_A', traffic_pattern='port_scan')
# This would connect to Flower server
# flwr.client.start_client(...)
"
```

---

## Troubleshooting

### Import Errors

If you get import errors, ensure:
1. You're in the correct directory
2. `requirements.txt` is installed
3. Python path includes parent directory

### Flower Connection Issues

- Check firewall settings
- Verify port 8080 is available
- Use `127.0.0.1` instead of `localhost` on Windows

### Simulation Hangs

- Use Ctrl+C to interrupt
- Check logs in `federated/logs/`

---

## Next Steps (Day 2-5)

- Day 2: Real packet capture integration
- Day 3: Rule sharing between clients
- Day 4: Differential privacy
- Day 5: Performance optimization

---

## Files Created

| File | Description |
|------|-------------|
| `federated/__init__.py` | Package initialization |
| `federated/utils.py` | Serialization & FedAvg |
| `federated/client.py` | MinimalFederatedClient |
| `federated/server.py` | FederatedServer |
| `federated/simulation.py` | Traffic simulators |
| `federated/test_federation.py` | Test suite |
| `federated/verify_install.py` | Verification script |
| `federated/dashboard_integration.py` | Flask API |
| `requirements.txt` | Updated with dependencies |
| `DAY1_TODO.md` | Task tracking |

