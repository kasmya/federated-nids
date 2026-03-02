# Quick Reference Card - Research Paper

## LaTeX-Ready Tables

### Table 1: System Performance
```latex
\begin{table}[h]
\centering
\caption{System Performance on Synthetic Data}
\label{tab:performance}
\begin{tabular}{|l|c|c|c|}
\hline
\textbf{Metric} & \textbf{Value} & \textbf{Notes} \\
\hline
F1 Score & 0.8667 & Best configuration \\
Precision & 100\% & No false positives \\
Recall & 76.47\% & Some attacks missed \\
Detection Rate & 100\% & All attack types detected \\
\hline
\end{tabular}
\end{table}
```

### Table 2: Federated Learning Results
```latex
\begin{table}[h]
\caption{Federated Learning Results by Scenario}
\label{tab:federated}
\begin{tabular}{|l|c|c|c|}
\hline
\textbf{Scenario} & \textbf{Rounds} & \textbf{Global Rules} & \textbf{Accuracy} \\
\hline
IID & 10 & 2 & 99.5\% \\
Non-IID & 15 & 2 & 74.8\% \\
Zero-Day & 15 & 3 & 74.4\% \\
\hline
\end{tabular}
\end{table}
```

### Table 3: Non-IID Per-Client Results
```latex
\begin{table}[h]
\caption{Non-IID Scenario: Per-Client Performance}
\label{tab:clients}
\begin{tabular}{|l|c|c|c|}
\hline
\textbf{Client} & \textbf{Attack Focus} & \textbf{Accuracy} & \textbf{Rules} \\
\hline
Client A & Port Scan & 86.7\% & 2,138 \\
Client B & SYN Flood & 99.8\% & 2,452 \\
Client C & Mixed & 38.0\% & 230 \\
\hline
\end{tabular}
\end{table}
```

### Table 4: Detection Thresholds
```latex
\begin{table}[h]
\caption{Detection Thresholds by Attack Type}
\label{tab:thresholds}
\begin{tabular}{|l|c|c|}
\hline
\textbf{Attack Type} & \textbf{Primary Feature} & \textbf{Threshold} \\
\hline
Port Scan & port\_diversity & 50 \\
SYN Flood & connection\_rate & 15 \\
DDoS & packet\_rate & 30 \\
ICMP Flood & icmp\_count & 20 \\
DNS Amplification & dns\_query\_rate & 5 \\
\hline
\end{tabular}
\end{table}
```

### Table 5: 13 Traffic Features
```latex
\begin{table}[h]
\caption{Extracted Traffic Features}
\label{tab:features}
\begin{tabular}{|l|l|c|}
\hline
\textbf{Feature} & \textbf{Description} & \textbf{Type} \\
\hline
packet\_rate & Packets per second & float \\
port\_diversity & Unique destination ports & int \\
avg\_packet\_size & Average packet size (bytes) & float \\
min\_packet\_size & Minimum packet size & int \\
max\_packet\_size & Maximum packet size & int \\
connection\_rate & New connections per second & float \\
dns\_query\_rate & DNS queries per second & float \\
icmp\_count & Total ICMP packets & int \\
unique\_dst\_ips & Unique destination IPs & int \\
bytes\_per\_second & Throughput (bytes/sec) & float \\
active\_time & Session duration (seconds) & float \\
protocols & Protocol distribution & dict \\
tcp\_flags & TCP flag distribution & dict \\
\hline
\end{tabular}
\end{table}
```

### Table 6: Architecture Layers
```latex
\begin{table}[h]
\caption{Three-Layer Detection Architecture}
\label{tab:layers}
\begin{tabular}{|l|l|p{5cm}|}
\hline
\textbf{Layer} & \textbf{Name} & \textbf{Function} \\
\hline
Layer 1 & Guard & YARA signature-based detection \\
Layer 2 & Brain & Threshold-based anomaly detection on 13 features \\
Layer 3 & Teacher & Rule generation and adaptive learning \\
\hline
\end{tabular}
\end{table}
```

---

## Key Commands to Run

```bash
# 1. Single NIDS evaluation
python3 evaluate_direct.py

# 2. CICIDS evaluation  
python3 evaluate_cicids.py

# 3. Ablation study
python3 ablate_layers.py

# 4. Baseline comparison
python3 compare_baselines.py

# 5. Federated simulation
python federated/orchestrator.py non_iid --rounds 5

# 6. Research experiments
cd part2-federated-research
python -m experiments.run

# 7. Enhanced experiments (ML comparison)
python -m experiments.enhanced_run

# 8. Web dashboard
python3 nids_server.py
```

---

## File Structure Summary

```
nids-closed-loop/
├── closed_loop/                    # Core NIDS (3-layer detection)
│   ├── traffic_analyzer.py        # Feature extraction (13 features)
│   ├── anomaly_detector.py        # Layer 2: Anomaly detection
│   ├── rule_generator.py          # Layer 3: Rule generation
│   ├── baselines.py               # Adaptive thresholds
│   └── learning_db.py             # Persistent storage
│
├── federated/                      # Federated Learning
│   ├── orchestrator.py            # Multi-client orchestration
│   ├── rule_consensus.py          # NOVEL: Rule consensus engine
│   ├── server.py                  # FedAvg server
│   ├── client.py                  # FL client
│   └── enhanced_client.py         # Client with consensus
│
├── part2-federated-research/       # Research version
│   ├── core/                       # Minimal NIDS
│   ├── federation/                 # FL + Consensus
│   └── experiments/                # Experiments
│
├── evaluate_*.py                   # Evaluation scripts
├── ablate_layers.py               # Ablation study
└── compare_baselines.py           # Baseline comparison
```

---

## Novel Contributions to Highlight

1. **Rule Consensus Mechanism**: Multiple NIDS clients vote on detection rules; rules reaching consensus (2+ similar rules) are promoted to global status
2. **Closed-Loop Architecture**: Detection → Rule Generation → Improved Detection cycle
3. **Threshold-based FL**: Federated learning on detection thresholds (not ML model weights)
4. **Non-IID Adaptation**: Different attack patterns per client with consensus-based knowledge sharing

---

## Algorithm Pseudocode

\subsection{Rule Consensus Algorithm}
\begin{algorithm}
\caption{Rule Consensus Mechanism}
\begin{algorithmic}
\STATE Input: Rules from $N$ clients, threshold $\tau = 0.7$
\STATE Initialize: votes $\leftarrow \{\}$, global\_rules $\leftarrow \{\}$
\FOR{client $c_i$ in clients}
    \FOR{rule $r$ in client\_rules[$c_i$]}
        \STATE Find similar rules in votes using Levenshtein + Jaccard
        \IF{similar rule exists with score $\ge \tau$}
            \STATE Add vote to similar rule
            \IF{votes $\ge 2$}
                \STATE Promote to global\_rules
                \STATE Distribute to all clients
            \ENDIF
        \ELSE
            \STATE Create new vote entry
        \ENDIF
    \ENDFOR
\ENDFOR
\STATE Return: global\_rules
\end{algorithmic}
\end{algorithm}

---

*Quick Reference Generated: 2026-03-02*

