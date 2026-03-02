# Federated NIDS Research

Minimal research codebase demonstrating federated learning for network intrusion detection.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run experiments
python -m experiments.run
```

## Structure

```
core/           # Minimal NIDS (detection + rules)
federation/     # Federated learning + consensus
experiments/    # Run experiments
results/        # Output directory
```

## Novel Contribution

See `federation/consensus.py` - The Rule Consensus Engine that enables
multiple NIDS clients to collaborate without sharing raw data.

## Expected Output

- 3 clients generate local rules
- Similar rules reach consensus
- Global rules promoted and shared
- Results saved to `results/`
