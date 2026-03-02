#!/usr/bin/env python3
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
