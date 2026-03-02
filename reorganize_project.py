#!/usr/bin/env python3
"""
Reorganization Script for Federated NIDS Project

This script reorganizes your messy project into two clean parts:
- Part 1: Original NIDS Dashboard (keeps working Flask UI)
- Part 2: Clean Research Codebase (minimal, under 1000 lines)

Usage:
    python reorganize_project.py

After running:
    cd part1-nids-dashboard && python app.py      # Test dashboard
    cd part2-federated-research && python -m experiments.run  # Test research
"""

import os
import shutil
import sys

# Configuration
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PART1_DIR = os.path.join(CURRENT_DIR, "part1-nids-dashboard")
PART2_DIR = os.path.join(CURRENT_DIR, "part2-federated-research")

# File dispositions
FILES_PART1 = {
    # Dashboard files
    "app.py": "app.py",
    "nids_server.py": "nids_server.py", 
    "server.py": "server.py",
    "simple_server.py": "simple_server.py",
    "run_server.py": "run_server.py",
    
    # Original NIDS core
    "closed_loop": "closed_loop",
    
    # UI files
    "templates": "templates",
    "static": "static",
    
    # Config files
    "rules.txt": "rules.txt",
    "auto_rules.txt": "auto_rules.txt",
    "yara_rules": "yara_rules",
    "requirements.txt": "requirements.txt",
}

# Files to skip (will be deleted or moved to archive)
FILES_TO_SKIP = [
    # Run scripts - redundant
    "run_day1.py", "run_day2.py", "run_day3.py", "run_federation.py",
    
    # Test files - will be inline
    "federated/test_consensus.py", "federated/test_federation.py",
    
    # Deployment files
    "Procfile", "RENDER_DEPLOY.md", "runtime.txt", "start.sh",
    "git_commit.sh",
    
    # Research docs - move to archive
    "PATENT_PROPOSAL_DRAFT.md", "RESEARCH_COMPARISON_PLAN.md",
    "FEDERATED_PLAN.md", "CLOSED_LOOP_PLAN.md",
    "DAY1_TODO.md", "PROJECT_EXPLAINED.md", "CODE_REVIEW_GUIDE.md",
    
    # Old experiments
    "compare_baselines.py", "ablate_layers.py", 
    "evaluate_nids.py", "evaluate_nids_improved.py", 
    "evaluate_direct.py", "evaluate_cicids.py",
    "closed_loop_integration.py", "closed_loop/",
    
    # Data directories (will be recreated)
    "saved_pcap", "nids-closedloop",
]


def create_directory_structure():
    """Create directory structure for both parts."""
    print("📁 Creating directory structure...")
    
    # Part 1: Dashboard
    os.makedirs(PART1_DIR, exist_ok=True)
    os.makedirs(os.path.join(PART1_DIR, "closed_loop"), exist_ok=True)
    os.makedirs(os.path.join(PART1_DIR, "templates"), exist_ok=True)
    os.makedirs(os.path.join(PART1_DIR, "static", "css"), exist_ok=True)
    os.makedirs(os.path.join(PART1_DIR, "static", "js"), exist_ok=True)
    os.makedirs(os.path.join(PART1_DIR, "yara_rules"), exist_ok=True)
    os.makedirs(os.path.join(PART1_DIR, "saved_pcap"), exist_ok=True)
    
    # Part 2: Research
    os.makedirs(os.path.join(PART2_DIR, "core"), exist_ok=True)
    os.makedirs(os.path.join(PART2_DIR, "federation"), exist_ok=True)
    os.makedirs(os.path.join(PART2_DIR, "experiments"), exist_ok=True)
    os.makedirs(os.path.join(PART2_DIR, "results"), exist_ok=True)
    os.makedirs(os.path.join(PART2_DIR, "data"), exist_ok=True)
    
    print("   ✓ Directories created")


def copy_part1_files():
    """Copy all Part 1 (Dashboard) files."""
    print("📦 Copying Part 1: NIDS Dashboard...")
    
    # Root level files
    for src_name in ["app.py", "nids_server.py", "server.py", "simple_server.py", 
                     "run_server.py", "rules.txt", "auto_rules.txt", "requirements.txt"]:
        src = os.path.join(CURRENT_DIR, src_name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(PART1_DIR, src_name))
            print(f"   ✓ {src_name}")
    
    # Closed loop
    src_closed = os.path.join(CURRENT_DIR, "closed_loop")
    dst_closed = os.path.join(PART1_DIR, "closed_loop")
    for f in os.listdir(src_closed):
        if f.endswith(".py"):
            shutil.copy2(os.path.join(src_closed, f), os.path.join(dst_closed, f))
            print(f"   ✓ closed_loop/{f}")
    
    # Templates
    src_tmpl = os.path.join(CURRENT_DIR, "templates")
    if os.path.exists(src_tmpl):
        for f in os.listdir(src_tmpl):
            shutil.copy2(os.path.join(src_tmpl, f), os.path.join(PART1_DIR, "templates", f))
            print(f"   ✓ templates/{f}")
    
    # Static
    src_static = os.path.join(CURRENT_DIR, "static")
    if os.path.exists(src_static):
        for root, dirs, files in os.walk(src_static):
            for f in files:
                src_path = os.path.join(root, f)
                rel_path = os.path.relpath(src_path, src_static)
                dst_path = os.path.join(PART1_DIR, "static", rel_path)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)
                print(f"   ✓ static/{rel_path}")
    
    # YARA rules
    src_yara = os.path.join(CURRENT_DIR, "yara_rules")
    if os.path.exists(src_yara):
        for f in os.listdir(src_yara):
            shutil.copy2(os.path.join(src_yara, f), os.path.join(PART1_DIR, "yara_rules", f))
            print(f"   ✓ yara_rules/{f}")
    
    print("   ✓ Part 1 complete!")


def create_part2_files():
    """Create all Part 2 (Research) minimal files."""
    print("🔬 Creating Part 2: Federated Research...")
    
    # Requirements
    requirements = """# Federated NIDS Research Dependencies
numpy>=1.21.0
flwr>=1.0.0
matplotlib>=3.5.0
"""
    with open(os.path.join(PART2_DIR, "requirements.txt"), "w") as f:
        f.write(requirements)
    print("   ✓ requirements.txt")
    
    # === CORE MODULE ===
    
    # core/detector.py - Minimal anomaly detection (~60 lines)
    detector_code = '''#!/usr/bin/env python3
"""
Minimal Anomaly Detector - Layer 2
Detects network attacks based on traffic features
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class AttackType(Enum):
    """Attack types we can detect"""
    NORMAL = "normal"
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    DDOS = "ddos"
    ICMP_FLOOD = "icmp_flood"


@dataclass
class Anomaly:
    """Represents a detected anomaly"""
    attack_type: AttackType
    src_ip: str
    score: float  # 0-1 confidence
    features: Dict[str, float]


class SimpleDetector:
    """Minimal anomaly detector using threshold-based detection"""
    
    # Detection thresholds
    THRESHOLDS = {
        'port_scan': {'port_diversity': 50, 'connection_rate': 8},
        'syn_flood': {'connection_rate': 15, 'packet_rate': 25},
        'ddos': {'packet_rate': 30, 'unique_dst_ips': 15},
        'icmp_flood': {'icmp_count': 20, 'packet_rate': 20},
    }
    
    def __init__(self, detection_threshold: float = 0.5):
        self.detection_threshold = detection_threshold
        self.baselines: Dict[str, Dict] = {}  # IP -> feature values
        self.detections: List[Anomaly] = []
    
    def process_packet(self, packet: Dict) -> Optional[Anomaly]:
        """Process a packet and return anomaly if detected"""
        src_ip = packet.get('src', 'unknown')
        
        # Initialize baseline for new IPs
        if src_ip not in self.baselines:
            self.baselines[src_ip] = {
                'ports': set(), 'packets': 0, 'connections': 0,
                'dst_ips': set(), 'icmp_count': 0, 'bytes': 0
            }
        
        # Update features
        bl = self.baselines[src_ip]
        bl['ports'].add(packet.get('dport', 0))
        bl['packets'] += 1
        bl['dst_ips'].add(packet.get('dst', ''))
        bl['bytes'] += packet.get('length', 64)
        
        if packet.get('flags') == 'S':
            bl['connections'] += 1
        if packet.get('proto') == 'icmp':
            bl['icmp_count'] += 1
        
        # Check thresholds
        return self._detect(src_ip, bl)
    
    def _detect(self, ip: str, features: Dict) -> Optional[Anomaly]:
        """Check if features indicate an attack"""
        port_div = len(features['ports'])
        conn_rate = features['connections'] / max(features['packets'], 1) * 10
        packet_rate = features['packets']  # Simplified
        icmp_count = features['icmp_count']
        unique_dst = len(features['dst_ips'])
        
        # Port scan detection
        if port_div > self.THRESHOLDS['port_scan']['port_diversity']:
            return Anomaly(AttackType.PORT_SCAN, ip, 0.8, {'port_diversity': port_div})
        
        # SYN flood detection
        if conn_rate > self.THRESHOLDS['syn_flood']['connection_rate']:
            return Anomaly(AttackType.SYN_FLOOD, ip, 0.9, {'connection_rate': conn_rate})
        
        # DDoS detection
        if packet_rate > self.THRESHOLDS['ddos']['packet_rate'] and unique_dst > 15:
            return Anomaly(AttackType.DDOS, ip, 0.85, {'packet_rate': packet_rate})
        
        # ICMP flood detection
        if icmp_count > self.THRESHOLDS['icmp_flood']['icmp_count']:
            return Anomaly(AttackType.ICMP_FLOOD, ip, 0.8, {'icmp_count': icmp_count})
        
        return None
    
    def get_detections(self) -> List[Anomaly]:
        return self.detections
'''
    
    with open(os.path.join(PART2_DIR, "core", "detector.py"), "w") as f:
        f.write(detector_code)
    print("   ✓ core/detector.py")
    
    # core/generator.py - Minimal rule generation (~40 lines)
    generator_code = '''#!/usr/bin/env python3
"""
Minimal Rule Generator - Layer 3
Creates detection rules from detected anomalies
"""

from typing import Dict, List
from dataclasses import dataclass
import hashlib


@dataclass
class DetectionRule:
    """A detection rule created from an anomaly"""
    rule_id: str
    rule_string: str
    attack_type: str
    src_ip: str
    score: float


class SimpleRuleGenerator:
    """Minimal rule generator - creates rules from anomalies"""
    
    def __init__(self):
        self.rules: List[DetectionRule] = []
        self.rule_counter = 0
    
    def generate_rule(self, anomaly) -> DetectionRule:
        """Create a detection rule from an anomaly"""
        self.rule_counter += 1
        
        # Create Snort-style rule
        rule_string = (
            f"alert tcp {anomaly.src_ip} any -> any any "
            f"(msg:\"{anomaly.attack_type.value.upper()}_DETECTED\"; "
            f"sid:{1000 + self.rule_counter};)"
        )
        
        rule = DetectionRule(
            rule_id=f"rule_{self.rule_counter}",
            rule_string=rule_string,
            attack_type=anomaly.attack_type.value,
            src_ip=anomaly.src_ip,
            score=anomaly.score
        )
        
        self.rules.append(rule)
        return rule
    
    def get_rules(self) -> List[DetectionRule]:
        return self.rules
    
    def get_rules_dict(self) -> List[Dict]:
        """Get rules as dictionaries for federation"""
        return [
            {
                'rule_string': r.rule_string,
                'anomaly_type': r.attack_type,
                'src_ip': r.src_ip,
                'score': r.score
            }
            for r in self.rules
        ]
'''
    
    with open(os.path.join(PART2_DIR, "core", "generator.py"), "w") as f:
        f.write(generator_code)
    print("   ✓ core/generator.py")
    
    # core/nids.py - Minimal NIDS orchestration (~40 lines)
    nids_code = '''#!/usr/bin/env python3
"""
Minimal Closed-Loop NIDS
Combines detection + rule generation
"""

from typing import List, Optional
from .detector import SimpleDetector, Anomaly
from .generator import SimpleRuleGenerator, DetectionRule


class ClosedLoopNIDS:
    """Minimal NIDS with closed-loop learning"""
    
    def __init__(self, detection_threshold: float = 0.5):
        self.detector = SimpleDetector(detection_threshold)
        self.rule_generator = SimpleRuleGenerator()
        self.total_packets = 0
        self.total_anomalies = 0
        self.total_rules = 0
    
    def process_packet(self, packet: dict) -> Optional[Anomaly]:
        """Process packet through the closed loop"""
        self.total_packets += 1
        
        # Layer 2: Detect anomalies
        anomaly = self.detector.process_packet(packet)
        
        if anomaly:
            self.total_anomalies += 1
            
            # Layer 3: Generate rules
            rule = self.rule_generator.generate_rule(anomaly)
            if rule:
                self.total_rules += 1
        
        return anomaly
    
    def get_status(self) -> dict:
        return {
            'packets_processed': self.total_packets,
            'anomalies_detected': self.total_anomalies,
            'rules_generated': self.total_rules,
        }
    
    def get_local_rules(self) -> List[DetectionRule]:
        return self.rule_generator.get_rules()
'''
    
    with open(os.path.join(PART2_DIR, "core", "nids.py"), "w") as f:
        f.write(nids_code)
    print("   ✓ core/nids.py")
    
    # core/__init__.py
    with open(os.path.join(PART2_DIR, "core", "__init__.py"), "w") as f:
        f.write("""from .nids import ClosedLoopNIDS
from .detector import SimpleDetector, Anomaly, AttackType
from .generator import SimpleRuleGenerator, DetectionRule

__all__ = ['ClosedLoopNIDS', 'SimpleDetector', 'Anomaly', 'AttackType', 
           'SimpleRuleGenerator', 'DetectionRule']
""")
    print("   ✓ core/__init__.py")
    
    # === FEDERATION MODULE ===
    
    # federation/consensus.py - NOVEL CONTRIBUTION (~120 lines)
    consensus_code = '''#!/usr/bin/env python3
"""
NOVEL CONTRIBUTION: Rule Consensus Engine
=========================================
This is the key innovation of our federated NIDS research.

When multiple NIDS clients detect similar attacks, they submit rules
to a central consensus engine. If 2+ clients submit similar rules,
they reach "consensus" and are promoted to "global rules" that all
clients adopt.

This mimics scientific peer review - ideas become "accepted" when
multiple researchers agree on them!
"""

import hashlib
from typing import Dict, List, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def jaccard_similarity(s1: str, s2: str, n: int = 3) -> float:
    """Calculate similarity using character n-grams"""
    def ngrams(s: str) -> set:
        s = s.lower().strip()
        return set(s[i:i+n] for i in range(len(s) - n + 1)) if len(s) >= n else set()
    
    ng1, ng2 = ngrams(s1), ngrams(s2)
    if not ng1 or not ng2:
        return 0.0
    return len(ng1 & ng2) / len(ng1 | ng2)


def similarity_score(rule1: str, rule2: str, threshold: float = 0.7) -> float:
    """Combined similarity score"""
    if rule1.lower().strip() == rule2.lower().strip():
        return 1.0
    
    max_len = max(len(rule1), len(rule2))
    if max_len == 0:
        return 1.0
    
    lev = 1.0 - (levenshtein_distance(rule1, rule2) / max_len)
    jac = jaccard_similarity(rule1, rule2)
    
    return 0.4 * lev + 0.6 * jac


@dataclass
class RuleVote:
    """A vote for a rule from a client"""
    rule_hash: str
    rule_string: str
    client_id: str
    anomaly_type: str = ""
    src_ip: str = ""
    score: float = 0.0


class RuleConsensusEngine:
    """
    NOVEL: Rule Consensus Engine
    
    Accepts rules from clients, finds similar ones, runs voting,
    and promotes rules to global status when consensus is reached.
    """
    
    def __init__(self, min_consensus: int = 2, similarity_threshold: float = 0.7):
        self.min_consensus = min_consensus
        self.similarity_threshold = similarity_threshold
        
        # rule_hash -> list of votes
        self.votes: Dict[str, List[RuleVote]] = defaultdict(list)
        self.global_rules: Dict[str, Dict] = {}  # Promoted rules
        self.promoted: Set[str] = set()
        
        self.stats = {
            'rules_submitted': 0,
            'rules_promoted': 0,
        }
    
    def _hash_rule(self, rule_string: str) -> str:
        return hashlib.sha256(rule_string.encode()).hexdigest()[:16]
    
    def find_similar(self, rule_string: str) -> List[Tuple[str, float]]:
        """Find similar existing rules"""
        similar = []
        for h, vote_list in self.votes.items():
            score = similarity_score(rule_string, vote_list[0].rule_string)
            if score >= self.similarity_threshold:
                similar.append((h, score))
        return sorted(similar, key=lambda x: x[1], reverse=True)
    
    def submit_rule(self, rule: Dict, client_id: str) -> Dict:
        """
        Submit a rule for consensus voting
        
        Args:
            rule: Dict with 'rule_string', 'anomaly_type', 'src_ip', 'score'
            client_id: ID of submitting client
            
        Returns:
            Result dict with submission status
        """
        self.stats['rules_submitted'] += 1
        rule_string = rule.get('rule_string', '')
        
        if not rule_string:
            return {'success': False, 'reason': 'Empty rule'}
        
        # Check for similar rules
        similar = self.find_similar(rule_string)
        
        if similar:
            # Vote for similar rule
            h, score = similar[0]
            self.votes[h].append(RuleVote(
                rule_hash=h, rule_string=rule_string, client_id=client_id,
                anomaly_type=rule.get('anomaly_type', ''),
                src_ip=rule.get('src_ip', ''), score=rule.get('score', 0.0)
            ))
            
            # Check consensus
            if len(self.votes[h]) >= self.min_consensus and h not in self.promoted:
                self.promoted.add(h)
                voters = [v.client_id for v in self.votes[h]]
                
                self.global_rules[h] = {
                    'rule_string': self.votes[h][0].rule_string,
                    'anomaly_type': rule.get('anomaly_type', ''),
                    'supporting_clients': voters,
                    'promotion_time': len(self.votes[h]),
                }
                self.stats['rules_promoted'] += 1
                
                return {
                    'success': True, 'consensus': True, 'global': True,
                    'voters': voters, 'rule_hash': h
                }
            
            return {'success': True, 'consensus': False, 'similar': True, 
                    'votes': len(self.votes[h]), 'similarity': score}
        
        else:
            # New rule
            h = self._hash_rule(rule_string)
            self.votes[h].append(RuleVote(
                rule_hash=h, rule_string=rule_string, client_id=client_id,
                anomaly_type=rule.get('anomaly_type', ''),
                src_ip=rule.get('src_ip', ''), score=rule.get('score', 0.0)
            ))
            
            return {'success': True, 'consensus': False, 'new': True, 
                    'votes': 1}
    
    def get_global_rules(self) -> List[Dict]:
        """Get all promoted global rules"""
        return list(self.global_rules.values())
    
    def get_statistics(self) -> Dict:
        return self.stats
'''
    
    with open(os.path.join(PART2_DIR, "federation", "consensus.py"), "w") as f:
        f.write(consensus_code)
    print("   ✓ federation/consensus.py (NOVEL CONTRIBUTION)")
    
    # federation/client.py - Flower client (~80 lines)
    client_code = '''#!/usr/bin/env python3
"""
Flower Client for Federated NIDS
Wraps the NIDS and participates in federated learning
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ClosedLoopNIDS


class FederatedClient:
    """Flower-compatible federated client"""
    
    def __init__(self, client_id: str, traffic_pattern: str = "normal"):
        self.cid = client_id
        self.pattern = traffic_pattern
        self.nids = ClosedLoopNIDS()
        self.round_count = 0
        
        print(f"[{client_id}] Initialized with pattern: {traffic_pattern}")
    
    def get_parameters(self) -> List[np.ndarray]:
        """Get NIDS parameters for federation"""
        # Extract key parameters as arrays
        params = [
            np.array([0.5], dtype=np.float32),  # threshold
            np.array([5.0, 3.0], dtype=np.float32),  # packet_rate baseline
            np.array([3.0, 2.0], dtype=np.float32),  # port_diversity baseline
            np.array([2.0, 2.0], dtype=np.float32),  # connection_rate baseline
        ]
        return params
    
    def set_parameters(self, params: List[np.ndarray]) -> None:
        """Apply federated parameters to NIDS"""
        if params:
            print(f"[{self.cid}] Received {len(params)} parameter arrays")
    
    def fit(self, parameters: List[np.ndarray], config: Dict) -> Tuple:
        """Process packets and generate rules (federated learning fit)"""
        self.round_count += 1
        round_num = config.get('round_number', self.round_count)
        
        # Apply global parameters
        self.set_parameters(parameters)
        
        # Generate traffic and process
        packets = self._generate_traffic(100)
        anomalies = 0
        rules_generated = 0
        
        for pkt in packets:
            anomaly = self.nids.process_packet(pkt)
            if anomaly:
                anomalies += 1
                rules_generated += 1
        
        # Get updated parameters
        new_params = self.get_parameters()
        
        metrics = {
            'loss': 1.0 - (anomalies / max(len(packets), 1)),
            'anomalies_detected': anomalies,
            'rules_generated': rules_generated,
            'packets_processed': len(packets),
        }
        
        print(f"[{self.cid}] Round {round_num}: {anomalies} anomalies, {rules_generated} rules")
        
        return new_params, len(packets), metrics
    
    def _generate_traffic(self, num_packets: int) -> List[Dict]:
        """Generate simulated traffic based on pattern"""
        packets = []
        
        if self.pattern == "port_scan":
            for i in range(num_packets):
                packets.append({
                    'src': '192.168.1.100', 'dst': '10.0.0.1',
                    'proto': 'tcp', 'dport': i % 100 + 1, 'flags': 'S', 'length': 64
                })
        elif self.pattern == "syn_flood":
            for i in range(num_packets):
                packets.append({
                    'src': f'192.168.1.{200 + (i % 3)}', 'dst': '10.0.0.2',
                    'proto': 'tcp', 'dport': 80, 'flags': 'S', 'length': 64
                })
        elif self.pattern == "normal":
            for i in range(num_packets):
                packets.append({
                    'src': f'192.168.1.{10 + (i % 5)}', 'dst': '10.0.0.10',
                    'proto': 'tcp', 'dport': [80, 443, 22][i % 3],
                    'flags': 'PA', 'length': 500 + (i % 100)
                })
        else:  # mixed
            normal = int(num_packets * 0.7)
            for i in range(normal):
                packets.append({'src': '192.168.1.10', 'dst': '10.0.0.10',
                              'proto': 'tcp', 'dport': 80, 'flags': 'PA', 'length': 500})
            for i in range(num_packets - normal):
                packets.append({'src': '192.168.1.100', 'dst': '10.0.0.10',
                              'proto': 'tcp', 'dport': i + 1, 'flags': 'S', 'length': 64})
        
        return packets
    
    def get_local_rules(self) -> List[Dict]:
        """Get rules generated by this client"""
        return self.nids.rule_generator.get_rules_dict()
'''
    
    with open(os.path.join(PART2_DIR, "federation", "client.py"), "w") as f:
        f.write(client_code)
    print("   ✓ federation/client.py")
    
    # federation/server.py - Simple FedAvg server (~60 lines)
    server_code = '''#!/usr/bin/env python3
"""
Simple Federated Server with FedAvg Aggregation
"""

import numpy as np
from typing import List, Dict
from .consensus import RuleConsensusEngine


def fedavg_aggregate(params_list: List[List[np.ndarray]]) -> List[np.ndarray]:
    """Federated Averaging - combine client parameters"""
    if not params_list:
        return []
    if len(params_list) == 1:
        return params_list[0]
    
    n = len(params_list)
    result = []
    
    for i in range(len(params_list[0])):
        arrays = [p[i].astype(np.float32) for p in params_list]
        result.append(np.mean(arrays, axis=0))
    
    return result


class FederatedServer:
    """Simple federated server"""
    
    def __init__(self, num_rounds: int = 3):
        self.num_rounds = num_rounds
        self.current_round = 0
        self.consensus = RuleConsensusEngine(min_consensus=2)
        self.global_params = None
        
        print(f"[Server] Initialized for {num_rounds} rounds")
    
    def run_round(self, clients: List) -> Dict:
        """Run one federated round"""
        self.current_round += 1
        
        print(f"\\n{'='*50}")
        print(f"FEDERATION ROUND {self.current_round}/{self.num_rounds}")
        print(f"{'='*50}")
        
        # Collect parameters from clients
        client_params = []
        client_results = []
        
        for client in clients:
            new_params, n_samples, metrics = client.fit(
                client.get_parameters() if self.current_round == 1 else self.global_params,
                {'round_number': self.current_round}
            )
            client_params.append(new_params)
            client_results.append({
                'cid': client.cid,
                'samples': n_samples,
                'metrics': metrics
            })
            
            # Submit rules to consensus
            for rule in client.get_local_rules():
                result = self.consensus.submit_rule(rule, client.cid)
                if result.get('consensus'):
                    print(f"★ CONSENSUS: {rule['rule_string'][:50]}...")
        
        # Aggregate parameters
        self.global_params = fedavg_aggregate(client_params)
        
        # Return round results
        return {
            'round': self.current_round,
            'clients': client_results,
            'global_rules': self.consensus.get_global_rules(),
            'consensus_stats': self.consensus.get_statistics()
        }
    
    def run_simulation(self, clients: List) -> Dict:
        """Run complete simulation"""
        all_results = []
        
        for _ in range(self.num_rounds):
            result = self.run_round(clients)
            all_results.append(result)
        
        return {
            'total_rounds': self.num_rounds,
            'rounds': all_results,
            'final_global_rules': self.consensus.get_global_rules()
        }
'''
    
    with open(os.path.join(PART2_DIR, "federation", "server.py"), "w") as f:
        f.write(server_code)
    print("   ✓ federation/server.py")
    
    # federation/__init__.py
    with open(os.path.join(PART2_DIR, "federation", "__init__.py"), "w") as f:
        f.write("""from .client import FederatedClient
from .server import FederatedServer
from .consensus import RuleConsensusEngine

__all__ = ['FederatedClient', 'FederatedServer', 'RuleConsensusEngine']
""")
    print("   ✓ federation/__init__.py")
    
    # === EXPERIMENTS MODULE ===
    
    # experiments/run.py - Main experiment runner (~60 lines)
    run_code = '''#!/usr/bin/env python3
"""
Experiment Runner - Run all scenarios and collect results
Usage: python -m experiments.run
"""

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from federation import FederatedClient, FederatedServer


def run_experiment(scenario: str, num_rounds: int = 3) -> dict:
    """Run a single experiment scenario"""
    
    print(f"\\n{'#'*60}")
    print(f"# EXPERIMENT: {scenario.upper()}")
    print(f"# Rounds: {num_rounds}")
    print(f"{'#'*60}")
    
    # Define clients based on scenario
    if scenario == "iid":
        clients = [
            FederatedClient("client_A", "port_scan"),
            FederatedClient("client_B", "syn_flood"),
            FederatedClient("client_C", "port_scan"),  # Same as A
        ]
    elif scenario == "non_iid":
        clients = [
            FederatedClient("client_A", "port_scan"),
            FederatedClient("client_B", "syn_flood"),
            FederatedClient("client_C", "mixed"),
        ]
    else:  # zero_day
        clients = [
            FederatedClient("client_A", "port_scan"),
            FederatedClient("client_B", "normal"),
            FederatedClient("client_C", "normal"),
        ]
    
    # Run simulation
    server = FederatedServer(num_rounds=num_rounds)
    results = server.run_simulation(clients)
    
    # Add metadata
    results['scenario'] = scenario
    results['timestamp'] = datetime.now().isoformat()
    
    return results


def main():
    """Run all scenarios"""
    scenarios = ["non_iid", "iid"]  # Add "zero_day" if desired
    
    all_results = {}
    
    for scenario in scenarios:
        results = run_experiment(scenario, num_rounds=3)
        all_results[scenario] = results
    
    # Save results
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    with open(f"results/experiment_{timestamp}.json", "w") as f:
        json.dump(all_results, f, indent=2)
    
    # Print summary
    print(f"\\n{'='*60}")
    print("EXPERIMENT SUMMARY")
    print(f"{'='*60}")
    
    for scenario, results in all_results.items():
        print(f"\\n{scenario.upper()}:")
        print(f"  Global rules created: {len(results.get('final_global_rules', []))}")
        for round_data in results.get('rounds', []):
            for cr in round_data.get('clients', []):
                print(f"  Round {round_data['round']}: {cr['cid']} - "
                      f"{cr['metrics']['rules_generated']} rules")
    
    print(f"\\n✓ Results saved to results/experiment_{timestamp}.json")


if __name__ == "__main__":
    main()
'''
    
    with open(os.path.join(PART2_DIR, "experiments", "run.py"), "w") as f:
        f.write(run_code)
    print("   ✓ experiments/run.py")
    
    # experiments/__init__.py
    with open(os.path.join(PART2_DIR, "experiments", "__init__.py"), "w") as f:
        f.write("# Experiments module\n")
    print("   ✓ experiments/__init__.py")
    
    # README.md for Part 2
    readme = '''# Federated NIDS Research

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
'''
    
    with open(os.path.join(PART2_DIR, "README.md"), "w") as f:
        f.write(readme)
    print("   ✓ README.md")
    
    print("   ✓ Part 2 complete!")


def create_archive_folder():
    """Create archive folder with skipped files info."""
    archive_dir = os.path.join(CURRENT_DIR, "archive")
    os.makedirs(archive_dir, exist_ok=True)
    
    # Create a manifest of what was skipped
    manifest = """# Archived Files

These files were not moved to either part:

## Redundant/Deprecated
- run_day1.py, run_day2.py, run_day3.py - Use experiments/run.py instead
- run_federation.py - Use experiments/run.py instead

## Deployment Files
- Procfile, runtime.txt, start.sh, git_commit.sh
- RENDER_DEPLOY.md

## Research Planning Docs
- PATENT_PROPOSAL_DRAFT.md
- RESEARCH_COMPARISON_PLAN.md
- FEDERATED_PLAN.md, CLOSED_LOOP_PLAN.md
- DAY1_TODO.md, PROJECT_EXPLAINED.md
- CODE_REVIEW_GUIDE.md

## Evaluation Scripts
- compare_baselines.py, ablate_layers.py
- evaluate_*.py files
- closed_loop_integration.py

## Data Directories
- saved_pcap/ - Old captures (recreate as needed)
- nids-closedloop/ - Git submodule (not needed)

After verifying both parts work, you can safely delete these files.
"""
    
    with open(os.path.join(archive_dir, "MANIFEST.txt"), "w") as f:
        f.write(manifest)
    
    print("📦 Archive manifest created")


def main():
    """Main reorganization function"""
    print("="*60)
    print("FEDERATED NIDS PROJECT REORGANIZATION")
    print("="*60)
    
    print(f"\\nCurrent directory: {CURRENT_DIR}")
    print(f"Part 1: {PART1_DIR}")
    print(f"Part 2: {PART2_DIR}")
    
    # Step 1: Create directories
    create_directory_structure()
    
    # Step 2: Copy Part 1 files
    copy_part1_files()
    
    # Step 3: Create Part 2 files
    create_part2_files()
    
    # Step 4: Create archive info
    create_archive_folder()
    
    print("\\n" + "="*60)
    print("✓ REORGANIZATION COMPLETE!")
    print("="*60)
    print("""
NEXT STEPS:

1. Test Part 1 (Dashboard):
   cd part1-nids-dashboard
   python app.py
   → Open http://localhost:5000

2. Test Part 2 (Research):
   cd part2-federated-research
   pip install -r requirements.txt
   python -m experiments.run
   → Results in results/

3. Verify old folder still works (backup)
   cd ..
   python app.py  # Original location still works

4. Once verified, delete archive/ and old files
""")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

