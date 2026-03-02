#!/usr/bin/env python3
"""
Federated NIDS - Day 2: Client with Rule Sharing
Modified MinimalFederatedClient with automatic rule submission and global rule polling
"""

import os
import sys
import time
import threading
import logging
from typing import Dict, Any, List, Optional, Tuple

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)


class FederatedClientWithRules:
    """
    Extended federated client with rule sharing capabilities.
    
    This client:
    - Generates rules during fit()
    - Submits rules to the consensus server
    - Polls for global rules
    - Adds received global rules to local rule generator
    
    Usage:
        client = FederatedClientWithRules(cid='client_A', server_url='http://localhost:5000')
        client.fit(parameters, config)
    """
    
    def __init__(
        self,
        cid: str,
        server_url: str = "http://localhost:5000",
        nids_config: Optional[Dict[str, Any]] = None,
        traffic_pattern: str = "normal",
        simulate_traffic: bool = True,
        poll_interval: int = 30,
        auto_submit_rules: bool = True
    ):
        """
        Initialize federated client with rule sharing.
        
        Args:
            cid: Client identifier
            server_url: URL of the Flask API server
            nids_config: Configuration for ClosedLoopNIDS
            traffic_pattern: Type of traffic to simulate
            simulate_traffic: Whether to use simulated packets
            poll_interval: Seconds between polling for global rules
            auto_submit_rules: Whether to automatically submit new rules
        """
        self.cid = cid
        self.server_url = server_url.rstrip('/')
        self.traffic_pattern = traffic_pattern
        self.poll_interval = poll_interval
        self.auto_submit_rules = auto_submit_rules
        
        # Track rules
        self.local_rules: List[Dict[str, Any]] = []
        self.submitted_rules: List[str] = []  # rule hashes
        self.global_rules_received: List[Dict[str, Any]] = []
        
        # Import and create base client
        from federated.client import MinimalFederatedClient
        
        print(f"\n[CLIENT {cid}] Initializing with rule sharing...")
        
        self.base_client = MinimalFederatedClient(
            cid=cid,
            nids_config=nids_config,
            traffic_pattern=traffic_pattern,
            simulate_traffic=simulate_traffic,
            rules_dir=f"federated/rules"
        )
        
        # Expose NIDS
        self.nids = self.base_client.nids
        
        # Statistics
        self.stats = {
            'rules_generated': 0,
            'rules_submitted': 0,
            'rules_promoted': 0,
            'global_rules_received': 0,
            'poll_count': 0,
        }
        
        # Polling thread
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_polling = threading.Event()
        
        print(f"[CLIENT {cid}] Rule sharing client initialized")
        print(f"  Server URL: {self.server_url}")
        print(f"  Poll interval: {self.poll_interval}s")
        print(f"  Auto submit: {self.auto_submit_rules}")
    
    # =========================================================================
    # RULE SUBMISSION
    # =========================================================================
    
    def get_local_rules(self) -> List[Dict[str, Any]]:
        """Get rules generated locally since last fetch."""
        # Get rules from rule generator
        all_rules = self.nids.rule_generator.get_all_rules()
        
        # Filter to new rules (not already tracked)
        new_rules = []
        for rule in all_rules:
            rule_hash = self._compute_hash(rule.get('rule_string', ''))
            
            # Skip if already tracked
            if rule_hash not in [self._compute_hash(r.get('rule_string', '')) for r in self.local_rules]:
                new_rules.append(rule)
        
        self.local_rules.extend(new_rules)
        return new_rules
    
    def submit_rules_to_server(self, rules: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Submit rules to the consensus server.
        
        Args:
            rules: List of rules to submit (optional, will fetch local if not provided)
            
        Returns:
            Result dictionary from server
        """
        if rules is None:
            rules = self.get_local_rules()
        
        if not rules:
            return {'status': 'no_rules', 'submitted': 0}
        
        try:
            import requests
            
            response = requests.post(
                f"{self.server_url}/api/federated/submit_rules",
                json={
                    'client_id': self.cid,
                    'rules': rules
                },
                timeout=5
            )
            
            result = response.json()
            
            # Update stats
            self.stats['rules_submitted'] += len(rules)
            
            promoted = result.get('rules_promoted', 0)
            self.stats['rules_promoted'] += promoted
            
            print(f"\n[CLIENT {self.cid}] Submitted {len(rules)} rules to server")
            if promoted > 0:
                print(f"[CLIENT {self.cid}] ★ {promoted} rule(s) promoted to global!")
            
            return result
            
        except Exception as e:
            print(f"[CLIENT {self.cid}] Error submitting rules: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _compute_hash(self, rule_string: str) -> str:
        """Compute hash of rule string."""
        import hashlib
        return hashlib.sha256(rule_string.encode()).hexdigest()[:16]
    
    # =========================================================================
    # GLOBAL RULE POLLING
    # =========================================================================
    
    def poll_global_rules(self) -> List[Dict[str, Any]]:
        """
        Poll server for new global rules.
        
        Returns:
            List of new global rules
        """
        try:
            import requests
            
            response = requests.get(
                f"{self.server_url}/api/federated/global_rules",
                timeout=5
            )
            
            result = response.json()
            all_global_rules = result.get('global_rules', [])
            
            # Find new rules
            new_global = []
            for rule in all_global_rules:
                rule_hash = rule.get('rule_hash', '')
                
                # Check if we already have this rule
                already_have = any(
                    r.get('rule_hash') == rule_hash 
                    for r in self.global_rules_received
                )
                
                if not already_have:
                    new_global.append(rule)
                    self.global_rules_received.append(rule)
            
            self.stats['global_rules_received'] += len(new_global)
            self.stats['poll_count'] += 1
            
            if new_global:
                print(f"\n[CLIENT {self.cid}] Received {len(new_global)} new global rule(s)")
                for rule in new_global:
                    print(f"  ★ {rule.get('rule_string', '')[:60]}...")
            
            return new_global
            
        except Exception as e:
            print(f"[CLIENT {self.cid}] Error polling global rules: {e}")
            return []
    
    def add_global_rule_to_local(self, rule: Dict[str, Any]) -> bool:
        """
        Add a global rule to local rule generator.
        
        Args:
            rule: Rule dictionary
            
        Returns:
            True if added successfully
        """
        try:
            # Create an AutoRule from the global rule
            from closed_loop.rule_generator import AutoRule
            
            auto_rule = AutoRule(
                src_ip=rule.get('src_ip', 'any'),
                anomaly_type=rule.get('anomaly_type', 'unknown'),
                rule_proto='tcp',
                dst_port=rule.get('dst_port', 'any'),
                message=rule.get('rule_string', '').split('(')[-1].rstrip(')'),
                score=rule.get('score', 0.5)
            )
            
            # Add to rule generator
            self.nids.rule_generator.auto_rules[auto_rule.id] = auto_rule
            
            print(f"[CLIENT {self.cid}] Added global rule to local: {auto_rule.message}")
            return True
            
        except Exception as e:
            print(f"[CLIENT {self.cid}] Error adding global rule: {e}")
            return False
    
    def _poll_loop(self):
        """Background polling loop."""
        print(f"[CLIENT {self.cid}] Started polling for global rules")
        
        while not self._stop_polling.is_set():
            try:
                # Poll for global rules
                new_rules = self.poll_global_rules()
                
                # Add each new rule locally
                for rule in new_rules:
                    self.add_global_rule_to_local(rule)
                
            except Exception as e:
                print(f"[CLIENT {self.cid}] Polling error: {e}")
            
            # Wait for next poll
            self._stop_polling.wait(self.poll_interval)
        
        print(f"[CLIENT {self.cid}] Stopped polling")
    
    def start_polling(self):
        """Start background polling for global rules."""
        if self._poll_thread is None or not self._poll_thread.is_alive():
            self._stop_polling.clear()
            self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._poll_thread.start()
            print(f"[CLIENT {self.cid}] Started polling thread")
    
    def stop_polling(self):
        """Stop background polling."""
        if self._poll_thread and self._poll_thread.is_alive():
            self._stop_polling.set()
            self._poll_thread.join(timeout=2)
            print(f"[CLIENT {self.cid}] Stopped polling thread")
    
    # =========================================================================
    # FIT AND EVALUATE (Extended from base client)
    # =========================================================================
    
    def fit(self, parameters: List[Any], config: Dict[str, Any]) -> Tuple[List[Any], int, Dict[str, Any]]:
        """
        Perform local training with rule sharing.
        
        This extends the base fit() to:
        1. Run local training (from base client)
        2. Submit generated rules to server
        3. Poll for global rules
        
        Args:
            parameters: Current global parameters
            config: Configuration dict
            
        Returns:
            Tuple of (updated parameters, num_samples, metrics)
        """
        round_num = config.get('round_number', 0)
        
        print(f"\n[CLIENT {self.cid}] === FIT ROUND {round_num} ===")
        
        # Call base fit (this generates rules via simulated traffic)
        new_params, num_samples, metrics = self.base_client.fit(parameters, config)
        
        # Update our rule stats
        local_rules = self.get_local_rules()
        self.stats['rules_generated'] = len(self.nids.rule_generator.get_all_rules())
        
        print(f"[CLIENT {self.cid}] Generated {len(local_rules)} new rule(s)")
        
        # Submit rules to server
        if self.auto_submit_rules and local_rules:
            submit_result = self.submit_rules_to_server(local_rules)
            metrics['rule_submission'] = submit_result
        
        # Poll for global rules
        new_global = self.poll_global_rules()
        
        # Add global rules locally
        for rule in new_global:
            self.add_global_rule_to_local(rule)
        
        # Update metrics
        metrics['rules_generated_total'] = self.stats['rules_generated']
        metrics['rules_submitted_total'] = self.stats['rules_submitted']
        metrics['global_rules_received'] = len(new_global)
        
        print(f"[CLIENT {self.cid}] FIT ROUND {round_num} COMPLETE")
        print(f"  Local rules: {self.stats['rules_generated']}")
        print(f"  Global rules received: {len(new_global)}")
        
        return new_params, num_samples, metrics
    
    def evaluate(self, parameters: List[Any], config: Dict[str, Any]) -> Tuple[float, int, Dict[str, Any]]:
        """Evaluate (delegates to base client)."""
        return self.base_client.evaluate(parameters, config)
    
    def get_parameters(self, config: Optional[Dict[str, Any]] = None) -> List[Any]:
        """Get parameters (delegates to base client)."""
        return self.base_client.get_parameters(config)
    
    def set_parameters(self, parameters: List[Any]) -> None:
        """Set parameters (delegates to base client)."""
        self.base_client.set_parameters(parameters)
    
    def get_status(self) -> Dict[str, Any]:
        """Get client status including rule sharing stats."""
        return {
            'cid': self.cid,
            'traffic_pattern': self.traffic_pattern,
            'nids_stats': self.nids.get_status(),
            'rule_stats': {
                'local_rules': len(self.local_rules),
                'rules_submitted': self.stats['rules_submitted'],
                'rules_promoted': self.stats['rules_promoted'],
                'global_rules_received': len(self.global_rules_received),
                'poll_count': self.stats['poll_count'],
            }
        }


# ============================================================================
# FACTORY FUNCTION
# ============================================================================

def create_client_with_rules(
    cid: str,
    server_url: str = "http://localhost:5000",
    traffic_pattern: str = "normal",
    **kwargs
) -> FederatedClientWithRules:
    """
    Factory function to create a federated client with rule sharing.
    
    Args:
        cid: Client identifier
        server_url: Server URL
        traffic_pattern: Traffic pattern
        **kwargs: Additional arguments
        
    Returns:
        FederatedClientWithRules instance
    """
    return FederatedClientWithRules(
        cid=cid,
        server_url=server_url,
        traffic_pattern=traffic_pattern,
        **kwargs
    )


# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("Federated Client with Rules - Test")
    print("="*60)
    
    # Create client (won't connect to server for this test)
    client = FederatedClientWithRules(
        cid='test_client',
        server_url='http://localhost:5000',
        traffic_pattern='port_scan',
        simulate_traffic=True,
        auto_submit_rules=False  # Don't try to connect
    )
    
    print(f"\n✓ Client created: {client.cid}")
    print(f"  NIDS: {type(client.nids).__name__}")
    
    # Test local rule generation
    print("\n--- Testing local rule generation ---")
    
    params = client.get_parameters()
    new_params, samples, metrics = client.fit(
        params,
        {'round_number': 1, 'num_packets': 50}
    )
    
    print(f"\n✓ Fit completed")
    print(f"  Samples: {samples}")
    print(f"  Rules generated: {metrics.get('rules_generated_total', 0)}")
    
    # Get local rules
    rules = client.get_local_rules()
    print(f"\n✓ Local rules: {len(rules)}")
    for rule in rules[:3]:
        print(f"  - {rule.get('rule_string', '')[:60]}...")
    
    print("\n✓ Test complete!")

