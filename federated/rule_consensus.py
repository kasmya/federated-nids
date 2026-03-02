#!/usr/bin/env python3
"""
Federated NIDS - Day 2: Rule Consensus Engine
Novel Contribution: Rule sharing and consensus mechanism for federated NIDS
"""

import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# RULE SIMILARITY ENGINE
# ============================================================================

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def jaccard_similarity(s1: str, s2: str) -> float:
    """Calculate Jaccard similarity using character trigrams."""
    def get_ngrams(s: str, n: int = 3) -> Set[str]:
        s = s.lower().strip()
        return set(s[i:i+n] for i in range(len(s) - n + 1)) if len(s) >= n else set()
    
    ngrams1 = get_ngrams(s1, 3)
    ngrams2 = get_ngrams(s2, 3)
    
    if not ngrams1 or not ngrams2:
        return 0.0
    
    intersection = len(ngrams1 & ngrams2)
    union = len(ngrams1 | ngrams2)
    return intersection / union if union > 0 else 0.0


def similarity_score(s1: str, s2: str) -> float:
    """Combined similarity score."""
    norm1 = s1.lower().strip()
    norm2 = s2.lower().strip()
    
    if norm1 == norm2:
        return 1.0
    
    max_len = max(len(norm1), len(norm2))
    if max_len == 0:
        return 1.0
    
    lev_dist = levenshtein_distance(norm1, norm2)
    lev_sim = 1.0 - (lev_dist / max_len)
    jac_sim = jaccard_similarity(norm1, norm2)
    
    return 0.4 * lev_sim + 0.6 * jac_sim


def rules_are_similar(rule1: str, rule2: str, threshold: float = 0.7) -> bool:
    """Check if two rules are similar enough."""
    score = similarity_score(rule1, rule2)
    return score >= threshold


# ============================================================================
# VOTING MECHANISM
# ============================================================================

@dataclass
class RuleVote:
    """Represents a vote for a rule from a client."""
    rule_hash: str
    rule_string: str
    client_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    anomaly_type: str = ""
    src_ip: str = ""
    score: float = 0.0


class VotingMechanism:
    """Tracks votes from clients for rules."""
    
    def __init__(self, min_votes: int = 2):
        self.min_votes = min_votes
        self.votes: Dict[str, List[RuleVote]] = defaultdict(list)
        self.promoted_rules: Set[str] = set()
        self.stats = {
            'total_votes': 0,
            'promoted_count': 0,
            'votes_by_client': defaultdict(int),
        }
    
    def compute_rule_hash(self, rule_string: str) -> str:
        return hashlib.sha256(rule_string.encode()).hexdigest()[:16]
    
    def submit_vote(self, rule: Dict[str, Any], client_id: str) -> Tuple[bool, str]:
        rule_string = rule.get('rule_string', '')
        if not rule_string:
            return "No rule string provided", ""
        
        rule_hash = self.compute_rule_hash(rule_string)
        
        # Check if client already voted
        for vote in self.votes[rule_hash]:
            if vote.client_id == client_id:
                return f"Client {client_id} already voted", rule_hash
        
        vote = RuleVote(
            rule_hash=rule_hash,
            rule_string=rule_string,
            client_id=client_id,
            anomaly_type=rule.get('anomaly_type', ''),
            src_ip=rule.get('src_ip', ''),
            score=rule.get('score', 0.0)
        )
        
        self.votes[rule_hash].append(vote)
        self.stats['total_votes'] += 1
        self.stats['votes_by_client'][client_id] += 1
        
        # Check for consensus
        if len(self.votes[rule_hash]) >= self.min_votes:
            if rule_hash not in self.promoted_rules:
                self.promoted_rules.add(rule_hash)
                self.stats['promoted_count'] += 1
                return f"CONSENSUS REACHED!", rule_hash
        
        return f"Vote recorded ({len(self.votes[rule_hash])}/{self.min_votes})", rule_hash
    
    def get_rule_votes(self, rule_hash: str) -> List[RuleVote]:
        return self.votes.get(rule_hash, [])
    
    def find_similar_votes(self, rule_string: str, threshold: float = 0.7) -> List[Tuple[str, float]]:
        similar = []
        for existing_hash, votes in self.votes.items():
            existing_string = votes[0].rule_string
            score = similarity_score(rule_string, existing_string)
            if score >= threshold:
                similar.append((existing_hash, score))
        return sorted(similar, key=lambda x: x[1], reverse=True)
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            'total_votes': self.stats['total_votes'],
            'unique_rules': len(self.votes),
            'promoted_count': self.stats['promoted_count'],
            'votes_by_client': dict(self.stats['votes_by_client']),
            'min_votes_required': self.min_votes,
        }


# ============================================================================
# RULE PROMOTION LOGIC
# ============================================================================

class RulePromotionManager:
    """Manages promotion of rules to global status."""
    
    def __init__(self, voting_mechanism: VotingMechanism, similarity_threshold: float = 0.7):
        self.voting = voting_mechanism
        self.similarity_threshold = similarity_threshold
        self.global_rules: Dict[str, Dict[str, Any]] = {}
        self.promotion_history: List[Dict[str, Any]] = []
        self.on_promote = None
    
    def check_and_promote(self, rule: Dict[str, Any], client_id: str) -> Optional[Dict[str, Any]]:
        """Check if rule should be promoted and promote if consensus reached."""
        rule_string = rule.get('rule_string', '')
        new_rule_hash = self.voting.compute_rule_hash(rule_string)
        
        # Check for similar existing rules
        similar = self.voting.find_similar_votes(rule_string, self.similarity_threshold)
        
        print(f"\n[CONSENSUS] Rule from {client_id}:")
        print(f"  {rule_string[:70]}...")
        
        promoted_rule = None
        
        if similar:
            print(f"  Found {len(similar)} similar rule(s):")
            for sim_hash, score in similar[:3]:
                print(f"    - {sim_hash[:8]}... (similarity: {score:.2f})")
            
            # Add vote to most similar rule
            sim_hash, sim_score = similar[0]
            
            # Add vote for similar rule
            vote = RuleVote(
                rule_hash=sim_hash,
                rule_string=rule_string,
                client_id=client_id,
                anomaly_type=rule.get('anomaly_type', ''),
                src_ip=rule.get('src_ip', ''),
                score=rule.get('score', 0.0)
            )
            self.voting.votes[sim_hash].append(vote)
            self.voting.stats['total_votes'] += 1
            self.voting.stats['votes_by_client'][client_id] += 1
            
            new_rule_hash = sim_hash
            
            # Check if consensus reached
            if len(self.voting.votes[sim_hash]) >= self.voting.min_votes:
                if sim_hash not in self.voting.promoted_rules:
                    self.voting.promoted_rules.add(sim_hash)
                    self.voting.stats['promoted_count'] += 1
                    
                    # Create global rule
                    votes = self.voting.votes[sim_hash]
                    supporting = [v.client_id for v in votes]
                    
                    global_rule = {
                        'rule_string': votes[0].rule_string,
                        'rule_hash': sim_hash,
                        'anomaly_type': rule.get('anomaly_type', ''),
                        'src_ip': rule.get('src_ip', ''),
                        'dst_port': rule.get('dst_port', 'any'),
                        'score': rule.get('score', 0.0),
                        'supporting_clients': supporting,
                        'promotion_time': datetime.now().isoformat(),
                    }
                    
                    self.global_rules[sim_hash] = global_rule
                    self.promotion_history.append(global_rule)
                    
                    print(f"[CONSENSUS] ★ CONSENSUS REACHED! Rule promoted to global!")
                    print(f"  Supporting clients: {supporting}")
                    
                    promoted_rule = global_rule
        
        # Also submit vote for exact rule
        message, rule_hash = self.voting.submit_vote(rule, client_id)
        print(f"[CONSENSUS] {message}")
        
        return promoted_rule
    
    def get_global_rules(self) -> List[Dict[str, Any]]:
        return list(self.global_rules.values())
    
    def get_all_rules_with_votes(self) -> List[Dict[str, Any]]:
        all_rules = []
        for rule_hash, votes in self.voting.votes.items():
            if votes:
                first = votes[0]
                all_rules.append({
                    'rule_string': first.rule_string,
                    'rule_hash': rule_hash,
                    'votes': len(votes),
                    'supporting_clients': [v.client_id for v in votes],
                    'is_promoted': rule_hash in self.voting.promoted_rules,
                    'anomaly_type': first.anomaly_type,
                })
        return sorted(all_rules, key=lambda x: x['votes'], reverse=True)


# ============================================================================
# MAIN CONSENSUS ENGINE
# ============================================================================

class RuleConsensusEngine:
    """Main class combining all consensus components."""
    
    def __init__(self, min_consensus: int = 2, similarity_threshold: float = 0.7):
        self.min_consensus = min_consensus
        self.similarity_threshold = similarity_threshold
        
        self.voting = VotingMechanism(min_votes=min_consensus)
        self.promotion = RulePromotionManager(self.voting, similarity_threshold)
        
        self.stats = {
            'rules_submitted': 0,
            'rules_promoted': 0,
            'consensus_rounds': 0,
        }
        
        print(f"[CONSENSUS] Engine initialized (min={min_consensus}, threshold={similarity_threshold})")
    
    def submit_rule(self, rule: Dict[str, Any], client_id: str) -> Dict[str, Any]:
        self.stats['rules_submitted'] += 1
        rule_string = rule.get('rule_string', 'unknown')
        
        # Check for similar existing rules first
        similar = self.voting.find_similar_votes(rule_string, self.similarity_threshold)
        
        if similar:
            print(f"\n[CONSENSUS] Similar rules found for {client_id}:")
            for sim_hash, score in similar[:2]:
                print(f"  - {sim_hash[:8]}... (similarity: {score:.2f})")
        
        # Submit rule for consensus
        result = self.promotion.check_and_promote(rule, client_id)
        
        if result:
            self.stats['rules_promoted'] += 1
            self.stats['consensus_rounds'] += 1
        
        return {
            'submitted': True,
            'rule_hash': self.voting.compute_rule_hash(rule_string),
            'similar_found': len(similar) > 0,
            'promoted': result is not None,
            'result': result
        }
    
    def get_global_rules(self) -> List[Dict[str, Any]]:
        return self.promotion.get_global_rules()
    
    def get_status(self) -> Dict[str, Any]:
        return {
            'engine_stats': self.stats,
            'voting_stats': self.voting.get_statistics(),
            'global_rules_count': len(self.global_rules),
            'global_rules': self.get_global_rules(),
        }
    
    @property
    def global_rules(self) -> Dict[str, Dict[str, Any]]:
        return self.promotion.global_rules


def create_consensus_engine(min_consensus: int = 2) -> RuleConsensusEngine:
    return RuleConsensusEngine(min_consensus=min_consensus)


if __name__ == '__main__':
    # Demo
    print("="*60)
    print("RULE CONSENSUS ENGINE DEMO")
    print("="*60)
    
    engine = RuleConsensusEngine(min_consensus=2)
    
    # Client A submits port scan
    print("\n--- Client A submits port scan ---")
    engine.submit_rule({
        'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.1 any (msg:"PORT_SCAN")',
        'anomaly_type': 'port_scan',
        'src_ip': '192.168.1.100',
        'score': 0.85
    }, 'client_A')
    
    # Client B submits SYN flood
    print("\n--- Client B submits SYN flood ---")
    engine.submit_rule({
        'rule_string': 'alert tcp 192.168.1.200 any -> 10.0.0.2 80 (msg:"SYN_FLOOD")',
        'anomaly_type': 'syn_flood',
        'src_ip': '192.168.1.200',
        'score': 0.90
    }, 'client_B')
    
    # Client C submits SIMILAR port scan (should trigger consensus!)
    print("\n--- Client C submits SIMILAR port scan ---")
    engine.submit_rule({
        'rule_string': 'alert tcp 192.168.1.100 any -> 10.0.0.5 any (msg:"PORT_SCAN_2")',
        'anomaly_type': 'port_scan',
        'src_ip': '192.168.1.100',
        'score': 0.80
    }, 'client_C')
    
    # Show results
    print("\n" + "="*60)
    print("GLOBAL RULES")
    print("="*60)
    for rule in engine.get_global_rules():
        print(f"\n★ {rule['rule_string'][:60]}...")
        print(f"  Supported by: {rule['supporting_clients']}")
    
    print(f"\nTotal promoted: {len(engine.get_global_rules())}")
    print("\n✓ Demo complete!")

