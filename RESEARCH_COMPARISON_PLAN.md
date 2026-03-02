# Research Paper Comparison & Ablation Study Plan

## Information Gathered

### Project Overview
This is a **NIDS Closed-Loop** system with a 3-layer detection architecture:
- **Layer 1 (Guard)**: Signature-based detection using YARA rules
- **Layer 2 (Brain)**: Threshold-based anomaly detection extracting 13 traffic features per IP
- **Layer 3 (Teacher)**: Adaptive learning with threshold training

### Key Features
- 13 traffic features: packet_rate, port_diversity, avg/min/max_packet_size, connection_rate, dns_query_rate, icmp_count, unique_dst_ips, bytes_per_second, active_time, protocols, tcp_flags
- Detection types: Port Scan, SYN Flood, DDoS, ICMP Flood, DNS Amplification
- Adaptive baselines with z-score anomaly detection
- Auto-generated rules from detected anomalies

### Current Performance Metrics
| Metric | Value | Source |
|--------|-------|--------|
| F1 Score | 0.8667 | Synthetic data (evaluate_direct.py) |
| Precision | 100% | Synthetic data |
| Recall | 76.47% | Synthetic data |
| Detection Rate | 100% | All attack types detected |

### Evaluation Scripts Available
1. `evaluate_direct.py` - Synthetic data with ground truth
2. `evaluate_cicids.py` - CICIDS2017 dataset evaluation
3. `evaluate_nids.py` - Basic NIDS evaluation
4. `evaluate_nids_improved.py` - Improved with training phase

---

## Plan: Research Paper Comparison & Ablation Study

### Phase 1: Published Baselines Comparison

#### 1.1 Identify Relevant Published Baselines
The following are well-known NIDS papers/datasets to compare against:

| Baseline | Paper/Dataset | Key Metrics to Compare |
|----------|---------------|------------------------|
| **CICIDS2017** | Sharafaldin et al. (2017) | Detection rate, F1, per-attack-type metrics |
| **NSL-KDD** | Tavallaee et al. (2009) | Accuracy, precision, recall |
| **UNSW-NB15** | Moustafa & Slay (2015) | F1 score, detection rate |
| **Botnet Detection** | Garcia et al. (2014) | Detection rate, false positive rate |
| **传统机器学习** | Multiple papers | Random Forest, SVM, DL approaches |

#### 1.2 Metrics to Report
For fair comparison, we need to report:
- **Per-attack-type detection rates**: Port Scan, SYN Flood, DDoS, ICMP Flood, DNS Amplification
- **Overall metrics**: F1 Score, Precision, Recall, Accuracy
- **False Positive Rate**: Critical for NIDS evaluation
- **Detection latency**: Time from attack start to detection

#### 1.3 Generate Comparable Results
Run evaluations on:
1. Synthetic data with known ground truth
2. CICIDS2017 subset (if available)
3. Generate attack scenarios matching published baselines

---

### Phase 2: Ablation Study Design

#### 2.1 Component Ablation Strategy
Systematically disable components to measure contribution:

| Configuration | Description | Expected Impact |
|---------------|-------------|-----------------|
| **Full System** | All 3 layers enabled | Baseline performance |
| **Layer 1 Only** | YARA rules only | Signature detection only |
| **Layer 2 Only** | Anomaly detection only | Without adaptive learning |
| **Layer 3 Disabled** | No auto rule generation | Without closed-loop learning |
| **No Adaptive Thresholds** | Fixed default thresholds | Without baseline adaptation |
| **Single Attack Type** | Test each attack separately | Per-attack performance |

#### 2.2 Ablation Scripts to Create

**Script 1: `ablate_layers.py`**
- Test each layer independently
- Measure F1, Precision, Recall per configuration

**Script 2: `ablate_thresholds.py`**
- Compare: Default vs Learned vs Adaptive thresholds
- Measure detection rate changes

**Script 3: `ablate_features.py`**
- Test with reduced feature sets
- Identify most important features per attack type

#### 2.3 Expected Ablation Results

```
Full System:           F1 = 0.8667 (baseline)
- Layer 1 only:       F1 = ??? (YARA signatures)
- Layer 2 only:       F1 = ??? (anomaly without learning)
- Layer 3 disabled:   F1 = ??? (no auto rules)
- Fixed thresholds:   F1 = ??? (no adaptation)
```

---

### Phase 3: Research Paper Content

#### 3.1 Required Sections

1. **Introduction**
   - Problem statement: Network intrusion detection
   - Proposed approach: Closed-loop 3-layer NIDS

2. **Related Work**
   - Traditional NIDS (Snort, Suricata)
   - Machine learning approaches
   - Deep learning approaches
   - Our contribution vs. state-of-art

3. **System Design**
   - Architecture diagram
   - Feature extraction (13 features)
   - Detection methodology
   - Closed-loop learning mechanism

4. **Evaluation**
   - Datasets used
   - Metrics
   - Comparison with baselines
   - Ablation study results

5. **Results Analysis**
   - Performance summary table
   - Per-attack-type breakdown
   - Ablation study insights

#### 3.2 Tables to Create

**Table 1: Comparison with Published Baselines**
| Method | Dataset | F1 Score | Precision | Recall |
|--------|---------|----------|-----------|--------|
| Our System | Synthetic | 0.8667 | 1.000 | 0.765 |
| Random Forest | CICIDS2017 | ~0.95 | ~0.92 | ~0.98 |
| CNN-LSTM | CICIDS2017 | ~0.97 | ~0.96 | ~0.98 |
| Isolation Forest | CICIDS2017 | ~0.85 | ~0.88 | ~0.82 |

**Table 2: Ablation Study Results**
| Configuration | F1 Score | Precision | Recall |
|---------------|----------|-----------|--------|
| Full System | 0.8667 | 1.000 | 0.765 |
| - Layer 1 (YARA) | - | - | - |
| - Layer 2 (Anomaly) | - | - | - |
| - Layer 3 (Learning) | - | - | - |

**Table 3: Per-Attack Detection Rates**
| Attack Type | Detection Rate | Avg Score |
|-------------|----------------|-----------|
| Port Scan | 100% | 0.51 |
| SYN Flood | 100% | 1.0 |
| DDoS | 100% | - |
| ICMP Flood | 100% | 0.75 |

---

### Phase 4: Implementation

#### 4.1 Files to Create/Modify

1. **Create `ablate_layers.py`** - Main ablation script
2. **Create `compare_baselines.py`** - Comparison script
3. **Create `research_results.py`** - Generate paper-ready results
4. **Modify evaluation scripts** - Add more detailed metrics

#### 4.2 Follow-up Steps

1. Run ablation study to get detailed metrics
2. Compare with 2-3 published baselines
3. Generate LaTeX-ready tables
4. Write results analysis

---

## Dependent Files to Edit

1. `ablate_layers.py` (new) - Main ablation study
2. `compare_baselines.py` (new) - Baseline comparison
3. `evaluate_direct.py` - May need modifications
4. `evaluate_cicids.py` - May need modifications

## Follow-up Steps After Implementation

1. Execute ablation study scripts
2. Collect all metrics
3. Create comparison tables
4. Write research paper results section

