# Closed-Loop NIDS Implementation Plan

## Information Gathered

### Existing Architecture:
1. **nids_server.py**: Main Flask server with:
   - `process_packet()`: Core packet handler that adds packets to state and checks rules
   - `check_packet_rules()`: Rule-based detection matching against rules.txt
   - `capture_state`: Thread-safe state management for packets/alerts
   - `start_capture()` / `stop_capture()`: Capture control
   - Simulation mode for demo when Scapy capture fails

2. **rules.txt**: Snort-style rules format:
   ```
   alert tcp any any --> any 22 SSH_DETECTED
   alert tcp 192.168.1.0/24 any --> any any INTERNAL_SCAN_DETECTED
   ```

3. **Frontend (app.js)**: HTTP polling every 2 seconds for:
   - `/api/status` - packet/alert counts
   - `/api/alerts` - detected alerts
   - `/api/packets` - captured traffic
   - `/api/rules` - loaded rules

4. **API Endpoints**: 
   - `GET /api/rules`, `POST /api/capture`, `GET /api/status`, `GET /api/alerts`

---

## Plan: Closed-Loop NIDS Implementation

### File Structure:
```
nids-web-dashboard/
├── nids_server.py          # Modified: Add integration points
├── rules.txt               # Modified: Support auto-generated rules section
├── auto_rules.txt          # NEW: Store auto-generated rules separately
├── closed_loop/
│   ├── __init__.py
│   ├── anomaly_detector.py # NEW: Layer 2 - Brain
│   ├── rule_generator.py   # NEW: Layer 3 - Teacher
│   ├── traffic_analyzer.py # NEW: Feature extraction
│   ├── baselines.py        # NEW: Adaptive baseline management
│   └── learning_db.py     # NEW: SQLite for learning metrics
└── templates/
    └── index.html          # Modified: UI for auto-learning status
```

### Implementation Details:

#### 1. Layer 2 - Brain (anomaly_detector.py)
**Features to Extract (5-10 simple features):**
- Packet rate (packets/second per IP)
- Port diversity (unique destination ports per IP)
- Packet size distribution (avg, min, max)
- Protocol distribution
- TCP flag patterns (SYN flood detection)
- Connection attempt rate
- DNS query patterns
- ICMP traffic volume

**Detection Methods:**
- Threshold-based detection (simple moving averages)
- Statistical anomaly detection (z-score)
- Pattern matching for known attack signatures

#### 2. Layer 3 - Teacher (rule_generator.py)
**Rule Generation Logic:**
- Port scan → Generate IP-based rule
- SYN flood → Generate flag-based rule  
- Anomaly pattern → Generate generic rule
- Duplicate prevention via hash checking
- Validation before deployment

#### 3. Integration Points in nids_server.py:
- Add packet buffer for batch analysis
- Hook anomaly detection after packet processing
- Add API endpoints for auto-learning status
- Reload rules when auto_rules.txt changes

#### 4. New API Endpoints:
- `GET /api/auto-learning/status` - Learning loop status
- `GET /api/auto-learning/anomalies` - Recent anomalies
- `GET /api/auto-learning/rules` - Auto-generated rules
- `POST /api/auto-learning/rule/:id/action` - Approve/reject rule
- `DELETE /api/auto-learning/rules/:id` - Remove rule

---

## Dependent Files to Edit:

1. **nids_server.py** - Main server (add integration points)
2. **rules.txt** - Add comments for auto-generated section
3. **Create new files in closed_loop/** directory
4. **static/js/app.js** - Add UI for auto-learning status
5. **templates/index.html** - Add auto-learning panel

---

## Followup Steps:

1. Create closed_loop/ directory structure
2. Implement anomaly_detector.py with feature extraction
3. Implement rule_generator.py for rule creation
4. Modify nids_server.py to integrate both layers
5. Add API endpoints for closed-loop control
6. Update frontend for auto-learning visualization
7. Test with simulated attacks (nmap, hping3)

---

## Example Flow:

```
1. User runs: nmap -sS 192.168.1.100 -p 1-1000
2. Layer 2 detects: High port diversity (100 ports in 5 sec)
3. Layer 2 flags: ANOMALY_PORT_SCAN (score: 0.85)
4. Layer 3 generates: alert tcp 192.168.1.100 any --> any any AUTO_PORT_SCAN_12345
5. Layer 3 validates: New rule, not duplicate ✓
6. Rule saved to auto_rules.txt
7. nids_server.py reloads rules
8. Layer 1 now catches future scans instantly
9. UI shows: "Auto-generated rule created: AUTO_PORT_SCAN_12345"
```

