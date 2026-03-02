# Step 2: Federated Learning Infrastructure Implementation Plan

## Information Gathered

### Current Architecture:
1. **Flask Dashboard** (`app.py`) - Main web interface with SocketIO
2. **Anomaly Detector** (`closed_loop/anomaly_detector.py`) - `SimpleAnomalyDetector` class
3. **Baselines** (`closed_loop/baselines.py`) - `AdaptiveBaseline` class with per-feature statistics
4. **Key Features to Federate**: 
   - Per-feature baseline values (mean/std): packet_rate, port_diversity, connection_rate, bytes_per_second, dns_query_rate, icmp_count
   - Detection thresholds
   - Adaptation rates

### Existing Components:
- `SimpleAnomalyDetector` uses `IPBaselineManager` which manages `AdaptiveBaseline` objects
- Each baseline stores: `baselines` dict with feature names → {'value': mean, 'std': std}
- Thread-safe with locks

---

## Plan

### 1. Flower Framework Setup
- Add `flwr` to requirements.txt
- Create installation verification script

### 2. Federated Client Wrapper
**File: `federated/client.py`**
- Create `FederatedNIDSClient` class that wraps `SimpleAnomalyDetector`
- Implement parameter serialization (extract mean/std values → NumPy arrays)
- Implement Flower client interface: `fit()`, `evaluate()`, `get_parameters()`, `set_parameters()`

### 3. Federated Server Implementation
**File: `federated/server.py`**
- Create `FederatedServer` class with:
  - FedAvg aggregation strategy
  - Client configuration
  - Round-based training
  - Statistics tracking

### 4. Test Setup with 2 Simulated Clients
**File: `federated/test_federation.py`**
- Run 2 client instances
- Server accepting connections
- Verify parameter exchange

### 5. Dashboard Integration
**Files: `app.py`, `templates/index.html`**
- Add federated API endpoints
- Add federation control panel to dashboard
- Display client status and statistics

---

## Dependent Files to be Edited
1. `requirements.txt` - Add Flower dependency
2. `app.py` - Add federated endpoints
3. `templates/index.html` - Add federated UI

## New Files to Create
1. `federated/__init__.py`
2. `federated/client.py` - Client wrapper
3. `federated/server.py` - Server implementation
4. `federated/test_federation.py` - Test script
5. `federated/utils.py` - Helper functions

## Followup Steps
1. Install dependencies
2. Test Flower installation
3. Run test federation with 2 clients
4. Verify parameter exchange
5. Test with dashboard integration

