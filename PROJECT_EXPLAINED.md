# NIDS Closed-Loop: Super Simple Explanation

---

## What is this project?

Imagine you're a security guard watching a door. You need to:
1. **Recognize bad people** (someone on your blacklist)
2. **Notice strange behavior** (someone carrying a bag, looking nervous)
3. **Remember what you learned** (update your blacklist after catching someone)

This project does the same thing - but for computer network traffic instead of people!

---

## The Problem It Solves

Computers send data in small chunks called "packets". Hackers can attack by:
- Checking all doors on your computer (Port Scan)
- Flooding your computer with fake requests (SYN Flood)
- Sending too much data (DDoS Attack)

This project detects these attacks automatically!

---

## The Simple Analogy

Think of a toll booth on a highway:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TOLL BOOTH ANALOGY                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Cars (Packets) ──▶ [ YOU ARE HERE ] ──▶ Highway               │
│                              │                                      │
│                              ▼                                      │
│                     ┌───────────────┐                               │
│                     │  Security     │                               │
│                     │  Guard        │                               │
│                     └───────────────┘                               │
│                              │                                      │
│              ┌───────────────┼───────────────┐                     │
│              ▼               ▼               ▼                      │
│        ┌─────────┐    ┌──────────┐   ┌───────────┐               │
│        │ Know    │    │ Notice   │   │ Remember  │               │
│        │ Bad     │    │ Strange  │   │ & Learn   │               │
│        │ Guys    │    │ Behavior │   │           │               │
│        └─────────┘    └──────────┘   └───────────┘               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## What Each File Does (Super Simple)

### 1. traffic_analyzer.py
**What it does**: Counts things about each computer talking on your network

Think of it like a teacher taking attendance:

```python
# Every time a computer sends data, we count:
- How many packets?           → packet_count
- How many different doors?    → port_diversity  
- How fast?                   → packet_rate
- How much data?              → bytes_per_second
```

**Simple example:**
```
Computer 192.168.1.10 sends 100 packets to port 80
→ We count: port_diversity = 1

Computer 192.168.1.10 sends to ports 80, 443, 22, 8080
→ We count: port_diversity = 4
```

### 2. anomaly_detector.py
**What it does**: Decides if something looks suspicious

Think of it like deciding if someone's behavior is strange:

```python
# If someone touches more than 50 doors, that's strange!
if ports_touched > 50:
    print("This looks like a PORT SCAN!")

# If someone knocks 15 times per second, that's strange!
if knocks_per_second > 15:
    print("This looks like a SYN FLOOD!")
```

### 3. baselines.py
**What it does**: Learns what's NORMAL for each computer

Think of it like learning someone's daily routine:

```python
# Your laptop normally:
# - Sends 5 packets per second
# - Talks to 3 different servers
# - Uses ports 80 and 443

# If suddenly:
# - Sends 100 packets per second  
# - Talks to 50 different servers
# - Uses 100 different ports
# → That's NOT normal! → ANOMALY!
```

### 4. rule_generator.py
**What it does**: Creates new rules when it catches an attack

Think of it like updating a wanted poster:

```python
# We caught an attacker!
# IP: 192.168.1.100
# Behavior: touching many ports

# Create a rule:
# "If 192.168.1.100 touches more than 10 ports, alert me!"

# Save this rule for the future!
```

---

## Step by Step Example

### Let's trace through a PORT SCAN attack:

**Step 1: Attacker starts scanning**
```
Attacker (192.168.1.100) sends packets to:
- 10.0.0.1:22   (SSH port)
- 10.0.0.1:23   (Telnet port)
- 10.0.0.1:80   (Web port)
- ... (50+ more ports)
```

**Step 2: System counts features**
```
For IP 192.168.1.100:
- port_diversity: 75   (touched 75 different ports)
- connection_rate: 12  (12 connections per second)
- packet_rate: 15     (15 packets per second)
```

**Step 3: Compare to thresholds**
```
Our rule: If port_diversity > 50 → ALERT!

75 > 50 → TRUE! → DETECTED!
```

**Step 4: Generate alert**
```
🚨 ALERT: Port Scan Detected!
- Attacker IP: 192.168.1.100
- Confidence: 75%
- Reason: Touched 75 ports in 10 seconds
```

**Step 5: Learn for future**
```
Create rule: "Block or monitor 192.168.1.100 if > 10 ports"
Save to database for next time!
```

---

## What is "Closed Loop"?

"Closed Loop" means the system learns from its detections:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      CLOSED LOOP DIAGRAM                           │
└─────────────────────────────────────────────────────────────────────┘

   DETECT ──▶ ALERT ──▶ LEARN ──▶ IMPROVE ──▶ DETECT
     ▲                                              │
     │                                              │
     └──────────────────────────────────────────────┘
     
     (System gets better over time!)
```

**Before:** System catches attack → Shows alert → Done
**Closed Loop:** System catches attack → Shows alert → Creates new rule → Uses rule for future detection → Catches attack faster next time!

---

## The 13 Features (What We Count)

Here's everything we count for each computer:

| # | Name | Simple Meaning | Example |
|---|------|---------------|---------|
| 1 | packet_rate | How fast sending data | 5 packets/second |
| 2 | port_diversity | How many different doors opened | 10 different ports |
| 3 | avg_packet_size | Average data chunk size | 500 bytes |
| 4 | min_packet_size | Smallest data chunk | 64 bytes |
| 5 | max_packet_size | Largest data chunk | 1500 bytes |
| 6 | connection_rate | How often starting new connections | 3 per second |
| 7 | dns_query_rate | How many DNS requests | 1 per second |
| 8 | icmp_count | How many "pings" | 0 |
| 9 | unique_dst_ips | How many different computers talked to | 5 |
| 10 | bytes_per_second | How much data per second | 1000 bytes/sec |
| 11 | active_time | How long been connected | 60 seconds |
| 12 | protocols | What type of traffic (TCP/UDP/ICMP) | {tcp: 10, udp: 5} |
| 13 | tcp_flags | What TCP flags seen | {S: 5, A: 10} |

---

## Attack Types We Detect

| Attack | What It Is | What We Look For |
|--------|-----------|------------------|
| **Port Scan** | Hacker checking all doors | Touches 50+ ports |
| **SYN Flood** | Fake connection spam | 15+ connections/sec |
| **DDoS** | Too much traffic | 30+ packets/sec to 15+ destinations |
| **ICMP Flood** | Too many pings | 20+ ICMP packets |
| **DNS Amplification** | DNS abuse | 5+ DNS queries, big responses |

---

## How To Run It

### Simple test:
```bash
# Start the server
python3 nids_server.py

# Open browser
# Go to http://localhost:5001
```

### Run evaluation:
```bash
# Test on synthetic data
python3 evaluate_direct.py

# Test on real dataset
python3 evaluate_cicids.py
```

---

## Summary

| Question | Answer |
|----------|--------|
| What does it do? | Detects network attacks automatically |
| How does it work? | Counts features, compares to thresholds, learns over time |
| What's special? | Closed-loop - learns from detections to improve |
| What attacks? | Port scan, SYN flood, DDoS, ICMP flood, DNS amplification |
| Performance? | 86.67% F1 score, 100% precision |

---

## If You Want To Understand More

Start by reading these files in order:
1. `closed_loop/traffic_analyzer.py` - What we count
2. `closed_loop/anomaly_detector.py` - How we decide
3. `closed_loop/baselines.py` - How we learn
4. `closed_loop/rule_generator.py` - How we remember



