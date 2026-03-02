# Federated Self-Learning NIDS - Complete System Documentation

## Executive Summary

This document provides comprehensive documentation of the Federated Self-Learning Network Intrusion Detection System (NIDS) built over 4 days. The system implements a novel closed-loop architecture with federated learning capabilities.

**Key Metrics:**
- Single NIDS F1 Score: 0.8667 (100% precision, 76.47% recall)
- Federated IID Accuracy: 99.5%
- Federated Non-IID Accuracy: 74.8%
- Zero-Day Detection: Supported via consensus mechanism

---

## Phase 1: Complete Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        FEDERATED SELF-LEARNING NIDS                            │
│                              SYSTEM OVERVIEW                                    │
└─────────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────────────────┐
                              │      WEB DASHBOARD          │
                              │   (Flask + SocketIO)        │
                              │   Real-time Monitoring      │
                              │   http://localhost:5001     │
                              └──────────────┬──────────────┘
                                             │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
                    ▼                         ▼                         ▼
        ┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
        │   CLIENT A        │    │   CLIENT B        │    │   CLIENT C        │
        │ (Port Scan Focus) │    │ (SYN Flood Focus) │    │ (Mixed Traffic)  │
        └─────────┬─────────┘    └─────────┬─────────┘    └─────────┬─────────┘
                  │                         │                         │
                  └─────────────────────────┼─────────────────────────┘
                                            │
                                            ▼
                          ┌─────────────────────────────────────────┐
                          │         FEDERATED SERVER                 │
                          │    (FedAvg + Rule Consensus Engine)      │
                          │         Port 8080 / Simulation           │
                          └─────────────────────────────────────────┘

================================================================================
                           DETAIL: SINGLE CLIENT ARCHITECTURE
================================================================================

┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT NODE                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│    PACKET INPUT                                                              │
│         │                                                                    │
│         ▼                                                                    │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │                    LAYER 1: GUARD (Signature)                    │      │
│  │  ┌─────────────────────────────────────────────────────────┐    │      │
│  │  │  YARA Rule Scanner                                       │    │      │
│  │  │  • malware_signatures.yar                                │    │      │
│  │  │  • rules1.yara                                           │    │      │
│  │  │  • auto_rules.txt (learned)                              │    │      │
│  │  └─────────────────────────────────────────────────────────┘    │      │
│  └──────────────────────────────────────────────────────────────────┘      │
│         │                                                                    │
│         ▼                                                                    │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │                    LAYER 2: BRAIN (Anomaly Detection)           │      │
│  │  ┌─────────────────────────────────────────────────────────┐    │      │
│  │  │  TrafficFeatureExtractor                                 │    │      │
│  │  │  • Extracts 13 features per source IP                   │    │      │
│  │  │  • Window-based analysis (default 10s)                  │    │      │
│  │  │                                                          │    │      │
│  │  │  FEATURES EXTRACTED:                                    │    │      │
│  │  │  1. packet_rate         8.  dns_query_rate               │    │      │
│  │  │  2. port_diversity     9.  icmp_count                   │    │      │
│  │  │  3. avg_packet_size   10.  unique_dst_ips                │    │      │
│  │  │  4. min_packet_size   11.  bytes_per_second              │    │      │
│  │  │  5. max_packet_size   12.  active_time                   │    │      │
│  │  │  6. connection_rate   13.  protocol_distribution         │    │      │
│  │  │  7. tcp_flags                                           │    │      │
│  │  └─────────────────────────────────────────────────────────┘    │      │
│  │                              │                                    │      │
│  │                              ▼                                    │      │
│  │  ┌─────────────────────────────────────────────────────────┐    │      │
│  │  │  SimpleAnomalyDetector / FeatureVector                   │    │      │
│  │  │                                                          │    │      │
│  │  │  THRESHOLD-BASED DETECTION:                             │    │      │
│  │  │  • port_scan: port_diversity > 50, connection_rate > 8  │    │      │
│  │  │  • syn_flood: connection_rate > 15, packet_rate > 25   │    │      │
│  │  │  • ddos: packet_rate > 30, unique_dst_ips > 15          │    │      │
│  │  │  • icmp_flood: icmp_count > 20, packet_rate > 20       │    │      │
│  │  │  • dns_amplification: dns_query_rate > 5               │    │      │
│  │  │                                                          │    │      │
│  │  │  ADAPTIVE THRESHOLDS:                                    │    │      │
│  │  │  • mean + (2.0 * std) for each feature                  │    │      │
│  │  │  • Computed per-network                                  │    │      │
│  │  └─────────────────────────────────────────────────────────┘    │      │
│  └──────────────────────────────────────────────────────────────────┘      │
│         │                                                                    │
│         ▼                                                                    │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │                    LAYER 3: TEACHER (Learning)                  │      │
│  │  ┌─────────────────────────────────────────────────────────┐    │      │
│  │  │  RuleGenerator                                           │    │      │
│  │  │  • Creates Snort-style rules from anomalies             │    │      │
│  │  │  • Rule format: alert tcp SRCIp any -> ...             │    │      │
│  │  │  • Each rule has: rule_id, attack_type, src_ip, score  │    │      │
│  │  └─────────────────────────────────────────────────────────┘    │      │
│  │                              │                                    │      │
│  │                              ▼                                    │      │
│  │  ┌─────────────────────────────────────────────────────────┐    │      │
│  │  │  LearningDB                                              │    │      │
│  │  │  • Stores learned patterns                               │    │      │
│  │  │  • Persistent rule storage                               │    │      │
│  │  │  • Historical baseline tracking                          │    │      │
│  │  └─────────────────────────────────────────────────────────┘    │      │
│  └──────────────────────────────────────────────────────────────────┘      │
│         │                                                                    │
│         ▼                                                                    │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │                    FEDERATION OUTPUT                              │      │
│  │  ┌─────────────────────────────────────────────────────────┐    │      │
│  │  │  • Detection parameters (thresholds, baselines)          │    │      │
│  │  │  • Generated rules                                        │    │      │
│  │  │  • Local metrics (packets, anomalies, rules)             │    │      │
│  │  └─────────────────────────────────────────────────────────┘    │      │
│  └──────────────────────────────────────────────────────────────────┘      │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

================================================================================
                    FEDERATED LEARNING + CONSENSUS ARCHITECTURE
================================================================================

                        ┌─────────────────────────────────────┐
                        │      RULE CONSENSUS ENGINE          │
                        │        (NOVEL CONTRIBUTION)         │
                        │                                     │
                        │  ┌─────────────────────────────┐  │
                        │  │  Similarity Detection       │  │
                        │  │  • Levenshtein distance    │  │
                        │  │  • Jaccard (n-gram 70%)    │  │
                        │  │  • Combined score: 0.4*L   │  │
                        │  │    + 0.6*J                  │  │
                        │  └─────────────────────────────┘  │
                        │              │                       │
                        │              ▼                       │
                        │  ┌─────────────────────────────┐  │
                        │  │  Voting Mechanism            │  │
                        │  │  • Min votes: 2              │  │
                        │  │  • Track per client         │  │
                        │  │  • Prevent duplicate votes  │  │
                        │  └─────────────────────────────┘  │
                        │              │                       │
                        │              ▼                       │
                        │  ┌─────────────────────────────┐  │
                        │  │  Rule Promotion              │  │
                        │  │  • 2+ similar rules →       │  │
                        │  │    CONSENSUS REACHED!       │  │
                        │  │  • Becomes GLOBAL RULE      │  │
                        │  │  • Distributed to ALL clients│  │
                        │  └─────────────────────────────┘  │
                        └─────────────────────────────────────┘

FEDERATION FLOW:

    ROUND START
        │
        ▼
    ┌─────────┐   ┌─────────┐   ┌─────────┐
    │CLIENT A │   │CLIENT B │   │CLIENT C │
    │Generate │   │Generate │   │Generate │
    │  50    │   │  50    │   │  50    │
    │  rules  │   │  rules  │   │  rules  │
    └────┬────┘   └────┬────┘   └────┬────┘
         │              │              │
         ▼              ▼              ▼
    ╔═══════════════════════════════════════╗
    ║     SUBMIT RULES TO CONSENSUS         ║
    ║     ENGINE (on server)                 ║
    ╚═══════════════════════════════════════╝
         │
         ▼
    ╔═══════════════════════════════════════╗
    ║     FIND SIMILAR RULES                 ║
    ║     (Similarity score >= 0.7)          ║
    ╚═══════════════════════════════════════╝
         │
         ▼
    ╔═══════════════════════════════════════╗
    ║     VOTE ON RULES                      ║
    ║     (Track votes per client)           ║
    ╚═══════════════════════════════════════╝
         │
         ▼
    ╔═══════════════════════════════════════╗
    ║     CHECK CONSENSUS (2+ votes)        ║
    ╠═══════════════════════════════════════╣
    ║     IF CONSENSUS:                      ║
    ║       → Promote to GLOBAL RULE          ║
    ║       → Add to global_rules             ║
    ║       → Distribute to ALL clients       ║
    ╚═══════════════════════════════════════╝
         │
         ▼
    ┌─────────┐   ┌─────────┐   ┌─────────┐
    │CLIENT A │◄──│CLIENT B │◄──│CLIENT C │
    │Receive  │   │Receive  │   │Receive  │
    │ GLOBAL  │   │ GLOBAL  │   │ GLOBAL  │
    │  RULES  │   │  RULES  │   │  RULES  │
    └─────────┘   └─────────┘   └─────────┘
         │
         ▼
    FEDAVG AGGREGATION
    (Combine detection parameters)
         │
         ▼
    ROUND COMPLETE

================================================================================
```

---

## Phase 2: Component Inventory

### Core NIDS Components (`closed_loop/`)

| File | Purpose | Dependencies | Key Functions |
|------|---------|--------------|---------------|
| `traffic_analyzer.py` | Feature extraction (13 features) | threading, collections | `extract_features()`, `_compute_features()`, `FeatureVector.calculate_anomaly_scores()` |
| `anomaly_detector.py` | Threshold-based detection | None (standalone) | `SimpleAnomalyDetector.process_packet()` |
| `rule_generator.py` | Creates Snort-style rules | None | `RuleGenerator.generate_rule()` |
| `baselines.py` | Adaptive threshold computation | numpy | `AdaptiveBaseline.compute()` |
| `learning_db.py` | Persistent storage | json, sqlite3 | `LearningDB.store()`, `LearningDB.query()` |
| `packet_capture_trainer.py` | Live threshold training | scapy | `PacketCaptureTrainer.capture_and_learn()` |

### Federated Components (`federated/`)

| File | Purpose | Dependencies | Key Functions |
|------|---------|--------------|---------------|
| `client.py` | FL client wrapper | flwr, numpy | `MinimalFederatedClient.get_parameters()`, `fit()`, `evaluate()` |
| `server.py` | FedAvg server | flwr, numpy | `FederatedServer.run_simulation()` |
| `orchestrator.py` | Multi-client orchestration | All clients | `FederatedOrchestrator.run_simulation()` |
| `rule_consensus.py` | **NOVEL** Rule voting | hashlib | `RuleConsensusEngine.submit_rule()`, `get_global_rules()` |
| `enhanced_client.py` | Client with consensus | rule_consensus | `EnhancedFederatedClient.fit_with_data()` |
| `utils.py` | FedAvg, serialization | numpy | `aggregate_parameters_fedavg()` |
| `dataset_generator.py` | Traffic generation | random, numpy | `generate_iid_partitions()`, `generate_all_partitions()` |

### Research Components (`part2-federated-research/`)

| File | Purpose | Dependencies |
|------|---------|--------------|
| `core/detector.py` | Minimal anomaly detector | enum, dataclasses |
| `core/generator.py` | Minimal rule generator | hashlib |
| `core/nids.py` | Closed-loop integration | detector, generator |
| `federation/client.py` | FL client (Flower) | numpy, core.nids |
| `federation/server.py` | FL server + consensus | numpy, consensus |
| `federation/consensus.py` | **NOVEL** Clean consensus impl | hashlib |
| `experiments/enhanced_run.py` | ML-based experiments | sklearn (optional) |

### Web Dashboard (`part1-nids-dashboard/`)

| File | Purpose |
|------|---------|
| `app.py` | Flask application |
| `templates/index.html` | Dashboard UI |
| `static/js/app.js` | Real-time updates |
| `yara_rules/*.yar` | Signature rules |

---

## Phase 3: Data Schema Documentation

### Packet Format
```python
{
    'src': '192.168.1.100',      # Source IP
    'dst': '10.0.0.1',           # Destination IP
    'proto': 'tcp',              # Protocol (tcp/udp/icmp)
    'dport': 80,                 # Destination port
    'sport': 12345,              # Source port
    'flags': 'S',                # TCP flags (S=Syn, A=Ack, P=Push)
    'length': 64,                # Packet size in bytes
    'timestamp': 1234567890.0    # Unix timestamp
}
```

### Feature Vector (13 Features)
```python
{
    'packet_rate': 5.0,          # Packets per second
    'port_diversity': 10,        # Unique destination ports
    'avg_packet_size': 500.0,   # Bytes
    'min_packet_size': 64,
    'max_packet_size': 1500,
    'connection_rate': 3.0,      # New connections/sec
    'dns_query_rate': 1.0,       # DNS queries/sec
    'icmp_count': 0,             # Total ICMP packets
    'unique_dst_ips': 5,         # Unique destinations
    'bytes_per_second': 2500.0,  # Throughput
    'active_time': 60.0,         # Seconds
    'protocols': {'tcp': 10, 'udp': 2},  # Distribution
    'tcp_flags': {'S': 5, 'A': 10}       # Flag counts
}
```

### Detection Rule Format
```python
{
    'rule_id': 'rule_001',
    'rule_string': 'alert tcp 192.168.1.100 any -> any any (msg:"PORT_SCAN_DETECTED"; sid:1001;)',
    'anomaly_type': 'port_scan',
    'src_ip': '192.168.1.100',
    'score': 0.85,               # Confidence 0-1
    'created_at': '2026-02-18T10:30:00'
}
```

### Federated Parameters
```python
{
    'detection_threshold': 0.5,
    'packet_rate_baseline': [mean, std],      # [5.0, 2.0]
    'port_diversity_baseline': [mean, std],   # [3.0, 1.5]
    'connection_rate_baseline': [mean, std],   # [2.0, 1.0]
    'bytes_per_second_baseline': [mean, std],  # [1000.0, 500.0]
    'adaptation_rate': 0.1
}
```

### Consensus Rule Vote
```python
{
    'rule_hash': 'a1b2c3d4e5f6',     # SHA256 first 16 chars
    'rule_string': 'alert tcp ...',
    'client_id': 'client_A',
    'anomaly_type': 'port_scan',
    'src_ip': '192.168.1.100',
    'score': 0.85,
    'timestamp': '2026-02-18T10:30:00'
}
```

### Global Promoted Rule
```python
{
    'rule_string': 'alert tcp 192.168.1.100 any -> any any (msg:"PORT_SCAN_DETECTED"; sid:1001;)',
    'rule_hash': 'a1b2c3d4e5f6',
    'anomaly_type': 'port_scan',
    'supporting_clients': ['client_A', 'client_B'],
    'promotion_time': 3,              # Number of votes
    'promoted_at': '2026-02-18T10:30:05'
}
```

---

## Phase 4: Configuration Parameters

### Detection Thresholds (Layer 2)
```python
DEFAULT_THRESHOLDS = {
    'port_scan': {
        'port_diversity': 50,       # Unique ports
        'connection_rate': 8,        # Conn/sec
    },
    'syn_flood': {
        'connection_rate': 15,      # SYN/sec
        'packet_rate': 25,          # Pkts/sec
    },
    'ddos': {
        'packet_rate': 30,
        'unique_dst_ips': 15,
    },
    'dns_amplification': {
        'dns_query_rate': 5,
        'avg_packet_size': 300,
    },
    'icmp_flood': {
        'icmp_count': 20,
        'packet_rate': 20,
    }
}
```

### Federation Configuration
```python
FEDERATION_CONFIG = {
    'num_rounds': 5,                # Default rounds
    'packets_per_round': 500,       # Packets per client per round
    'min_consensus_votes': 2,       # Votes needed for promotion
    'similarity_threshold': 0.7,    # Jaccard + Levenshtein threshold
    'client_configs': [
        {'cid': 'client_A', 'pattern': 'port_scan'},
        {'cid': 'client_B', 'pattern': 'syn_flood'},
        {'cid': 'client_C', 'pattern': 'mixed'},
    ]
}
```

### Experiment Scenarios
```python
SCENARIOS = {
    'iid': {
        'description': 'Same attack distribution across clients',
        'attack_rate': 0.25,        # 25% attacks
    },
    'non_iid': {
        'description': 'Different attack patterns per client',
        'client_A_attack_rate': 0.50,  # Port scan focus
        'client_B_attack_rate': 0.40,  # SYN flood focus
        'client_C_attack_rate': 0.10,  # Mostly normal
    },
    'zero_day': {
        'description': 'New attack type in later rounds',
        'new_attack_round': 5,
    }
}
```

---

## Phase 5: Integration Status & Gaps

### ✅ Connected Components

1. **Single NIDS Pipeline**: Packet → Feature Extraction → Anomaly Detection → Rule Generation → Learning DB
2. **Federated Learning Loop**: Client → Server (FedAvg) → Parameters Update
3. **Rule Consensus**: Local Rules → Similarity Check → Voting → Global Rules
4. **Web Dashboard**: Real-time monitoring with SocketIO

### ⚠️ Integration Gaps

| Gap | Severity | Description |
|-----|----------|-------------|
| Dashboard ↔ Federation | Medium | No UI for federation status, rules, consensus |
| Global rules → Layer 1 | Low | Global rules not automatically added to YARA |
| Zero-day explicit handling | Medium | Zero-day scenario uses non-iid fallback |
| Persistent federation state | Medium | Results saved to JSON but no DB |
| Real network capture in FL | High | Only simulated traffic in federation |

### 🔧 Fixes Needed

1. **Dashboard Integration**:
   ```python
   # Add to federated/dashboard_integration.py
   @app.route('/api/federation/status')
   def get_federation_status():
       return jsonify(orchestrator.get_status())
   ```

2. **Global Rules → YARA**:
   ```python
   def apply_global_rules(global_rules):
       for rule in global_rules:
           add_to_yara(rule['rule_string'])
   ```

3. **Real Packet Capture**:
   ```python
   # In EnhancedFederatedClient
   def set_data_source(self, capture_file):
       self.packets = load_pcap(capture_file)
   ```

---

## Phase 6: Experiment Results Summary

### Synthetic Data Evaluation
```
=================================================================
EVALUATION RESULTS - Synthetic Data
=================================================================
Best Configuration: threshold=0.1

Performance Metrics:
  ✓ F1 Score:    0.8667
  ✓ Precision:   100%
  ✓ Recall:      76.47%

Detection Breakdown:
  - port_scan:  Detected (score=0.51)
  - syn_flood: Detected (score=1.0)
  - icmp_flood: Detected (score=0.75)
=================================================================
```

### Federated Learning Results

| Scenario | Rounds | Global Rules | Avg Accuracy | Key Insight |
|----------|--------|--------------|-------------|-------------|
| **IID** | 10 | 2 | 99.5% | Consensus reached in round 1 |
| **Non-IID** | 15 | 2 | 74.8% | Different attack focus helps |
| **Zero-Day** | 15 | 3 | 74.4% | Consensus adapts to new patterns |

### Per-Client Performance (Non-IID)
```
Client A (Port Scan):  86.7% accuracy, 2138 rules generated
Client B (SYN Flood):  99.8% accuracy, 2452 rules generated  
Client C (Mixed):       38.0% accuracy, 230 rules generated
```

---

## Phase 7: Paper Preparation Checklist

### Code Artifacts (GitHub/Appendix)

- [x] Core NIDS (`closed_loop/`)
- [x] Federated components (`federated/`)
- [x] Research version (`part2-federated-research/`)
- [x] Web dashboard (`part1-nids-dashboard/`)
- [x] Experiment scripts (`experiments/enhanced_run.py`)
- [x] Evaluation scripts (`evaluate_*.py`)
- [x] Requirements.txt with all dependencies

### Experiment Results to Capture

- [x] Synthetic evaluation (F1=0.8667, Precision=100%, Recall=76.47%)
- [x] IID scenario results (99.5% accuracy)
- [x] Non-IID scenario results (74.8% accuracy)
- [x] Zero-Day scenario results (74.4% accuracy)
- [x] Ablation study results
- [x] Baseline comparison table
- [ ] Run enhanced experiments with sklearn (optional ML comparison)

### Visualizations Needed

- [x] Round-by-round accuracy graph
- [x] Rules generated over time
- [x] Communication cost (if measured)
- [ ] Federation vs. No-Federation comparison chart
- [ ] Consensus formation timeline
- [ ] Detection rate by attack type

### Methodology Details to Document

1. **Feature Extraction**: 13 features, 10-second sliding window
2. **Threshold Detection**: Static + adaptive (mean + 2σ)
3. **Closed-Loop Learning**: Rule generation from each anomaly
4. **Federated Averaging**: Parameter aggregation
5. **Rule Consensus**: Levenshtein + Jaccard similarity (0.7 threshold)
6. **Novelty Claim**: Rule consensus without sharing raw data

### Novelty Claims

1. **Rule Consensus Mechanism**: Multiple NIDS clients vote on detection rules; similar rules reaching consensus become global
2. **Closed-Loop Architecture**: Detection → Rule Generation → Improved Detection cycle
3. **Threshold-based FL**: Federated learning on detection thresholds rather than ML model weights
4. **Non-IID Handling**: Different attack patterns per client with consensus-based adaptation

---

## Phase 8: Step-by-Step Integration Plan

### Day 1: Complete Integration
1. Connect Dashboard to Federation Status
2. Add Global Rules → YARA automatic loading
3. Clean up experiment output formats

### Day 2: Run Comprehensive Experiments
```bash
# Run all scenarios with federation comparison
python -m part2_federated_research.experiments.enhanced_run

# Generate comparison charts
python part2_federated_research.experiments.visualize
```

### Day 3: Paper-Ready Outputs
1. Generate final visualization charts
2. Create LaTeX-ready tables
3. Document all parameters and algorithms
4. Write methodology section

---

## Appendix: Commands to Reproduce

```bash
# Single NIDS evaluation
python3 evaluate_direct.py

# CICIDS evaluation
python3 evaluate_cicids.py

# Ablation study
python3 ablate_layers.py

# Baseline comparison
python3 compare_baselines.py

# Federated simulation (Day 3 orchestrator)
python federated/orchestrator.py non_iid --rounds 5

# Research experiments
cd part2-federated-research
python -m experiments.run

# Enhanced ML comparison
python -m experiments.enhanced_run

# Web dashboard
python3 nids_server.py
```

---

*Generated: 2026-03-02*
*System: Federated Self-Learning NIDS v1.0*

